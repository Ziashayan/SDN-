import os
import logging
import time
import json
import numpy as np
import pandas as pd
import joblib
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Union
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.utils import assert_all_finite
from tensorflow.keras.models import Model, save_model, load_model
from tensorflow.keras.layers import Input, LSTM, Dense, Dropout, BatchNormalization, Attention, Concatenate, Conv1D, GlobalMaxPooling1D
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras import backend as K
from tensorflow.keras.utils import to_categorical
import tensorflow as tf

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids_model.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('IDSModel')

class IDSModel:
    """Advanced Hybrid LSTM-Attention Network Intrusion Detection System"""
    
    # Constants
    SEQUENCE_LENGTH = 10
    MIN_TRAINING_SAMPLES = 5000
    MODEL_VERSION = "3.0"  # Updated version
    RETRAIN_DAYS = 7
    ACCURACY_THRESHOLD = 0.85
    
    # Feature configuration
    NUMERIC_FEATURES = [
        'sbytes', 'dbytes', 'sttl', 'sload', 'dload',
        'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'dwin'
    ]
    
    CATEGORICAL_FEATURES = ['proto', 'service', 'state']
    
    # Protocol mappings
    PROTOCOL_MAP = {'tcp': 6, 'udp': 17, 'icmp': 1, 'igmp': 2, 'ip': 0}
    SERVICE_MAP = {
        'http': 80, 'https': 443, 'ssh': 22, 'smtp': 25, 'ftp': 21,
        'dns': 53, 'dhcp': 67, 'snmp': 161, 'ssl': 443, '-': 0
    }
    STATE_MAP = {
        'REQ': 1, 'RSP': 2, 'SYN': 3, 'ACK': 4, 'FIN': 5,
        'CON': 6, 'INT': 7, 'CLO': 8, 'ECO': 9, 'URN': 10
    }
    
    # Attack type mapping
    ATTACK_TYPES = {
        0: 'Normal',
        1: 'Generic',
        2: 'Exploits',
        3: 'Fuzzers',
        4: 'DoS',
        5: 'Reconnaissance',
        6: 'Analysis',
        7: 'Backdoor',
        8: 'Shellcode',
        9: 'Worms'
    }
    
    # Full feature names including engineered features
    ENGINEERED_FEATURES = [
        'bytes_ratio', 'packet_timing', 'load_ratio', 'win_ratio',
        'packet_size_diff', 'packet_size_sum', 'packet_jitter_diff',
        'packet_load_diff', 'packet_win_sum'
    ]

    def __init__(self, model_path: Optional[str] = None):
        """Initialize the IDS model with default or custom paths"""
        self.logger = logger
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Initialize model paths
        self.model_path = model_path or os.path.join(self.script_dir, "models", f"ids_model_v{self.MODEL_VERSION}.h5")
        self.scaler_path = os.path.join(self.script_dir, "models", "scaler.joblib")
        self.encoder_path = os.path.join(self.script_dir, "models", "label_encoder.joblib")
        self.selector_path = os.path.join(self.script_dir, "models", "feature_selector.joblib")
        
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Model components
        self.model = None
        self.scaler = None
        self.encoder = None
        self.selector = None
        self.selected_features = []
        self.selected_feature_indices = []
        
        # Full feature names
        self.all_feature_names = (
            self.NUMERIC_FEATURES + 
            self.CATEGORICAL_FEATURES + 
            self.ENGINEERED_FEATURES
        )
        
        # Model metadata with safe defaults
        self.model_info = {
            'version': self.MODEL_VERSION,
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'last_trained': 0,
            'training_time': 0,
            'health_status': 'untrained',
            'input_shape': None,
            'cv_accuracy': 0.0,
            'cv_f1': 0.0
        }
        
        # Attack monitoring
        self.attack_stats = defaultdict(lambda: {'count': 0, 'first_seen': 0, 'last_seen': 0})
        self.realtime_attacks = deque(maxlen=1000)
        self.sequence_buffer = deque(maxlen=self.SEQUENCE_LENGTH)
        
        # Load existing model if available
        self._load_model()

    def needs_training(self) -> bool:
        """Determine if model requires retraining based on multiple factors"""
        try:
            # Always train if no model exists
            if self.model is None:
                return True
                
            # Check if model was never trained
            if self.model_info['last_trained'] == 0:
                return True
                
            # Calculate time since last training
            days_since_training = (time.time() - self.model_info['last_trained']) / 86400
            
            # Check retraining conditions
            if (days_since_training > self.RETRAIN_DAYS or
                self.model_info['health_status'] == 'poor' or
                self.model_info['accuracy'] < self.ACCURACY_THRESHOLD):
                return True
                
            return False
        except Exception as e:
            self.logger.error(f"Error in training needs assessment: {str(e)}")
            return True  # Default to needing training if check fails

    def _load_model(self) -> bool:
        """Load model and preprocessing artifacts from disk"""
        try:
            # Check if all required files exist
            required_files = [
                self.model_path, self.scaler_path,
                self.encoder_path, self.selector_path,
                f"{self.selector_path}.features",
                f"{self.selector_path}.indices"
            ]
            
            if not all(os.path.exists(p) for p in required_files):
                self.logger.info("Some model files are missing, loading aborted")
                return False
                
            custom_objects = {
                'Attention': Attention,
                'focal_loss': self._focal_loss
            }
            
            self.model = load_model(self.model_path, custom_objects=custom_objects)
            self.scaler = joblib.load(self.scaler_path)
            self.encoder = joblib.load(self.encoder_path)
            self.selector = joblib.load(self.selector_path)
            self.selected_features = joblib.load(f"{self.selector_path}.features")
            self.selected_feature_indices = joblib.load(f"{self.selector_path}.indices")
            
            if hasattr(self.model, 'input_shape'):
                self.model_info['input_shape'] = self.model.input_shape[1:]
                self.model_info['health_status'] = self._get_health_status(self.model_info['accuracy'])
            
            self.logger.info("Model loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Model loading failed: {str(e)}")
            return False

    def _save_model(self) -> bool:
        """Save model and preprocessing artifacts to disk"""
        try:
            save_model(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            joblib.dump(self.encoder, self.encoder_path)
            joblib.dump(self.selector, self.selector_path)
            joblib.dump(self.selected_features, f"{self.selector_path}.features")
            joblib.dump(self.selected_feature_indices, f"{self.selector_path}.indices")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            return False

    def _focal_loss(self, y_true, y_pred, gamma: float = 2.0, alpha: float = 0.25):
        """Focal loss implementation for handling class imbalance"""
        y_pred = K.clip(y_pred, K.epsilon(), 1.0 - K.epsilon())
        ce = -y_true * K.log(y_pred)
        weight = alpha * K.pow(1.0 - y_pred, gamma)
        fl = weight * ce
        return K.mean(fl, axis=-1)

    def _get_dataset_path(self, filename: str) -> Optional[str]:
        """Locate dataset file in common directories"""
        search_paths = [
            os.path.join(self.script_dir, "datasets", filename),
            os.path.join(self.script_dir, filename),
            os.path.join("/data/ids/datasets", filename)
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                return path
        return None

    def _preprocess_packet(self, packet: Dict) -> np.ndarray:
        """Convert raw packet data into processed feature vector"""
        try:
            features = []
            
            # Process numeric features
            for feat in self.NUMERIC_FEATURES:
                features.append(float(packet.get(feat, 0)))
            
            # Process categorical features
            for feat in self.CATEGORICAL_FEATURES:
                value = packet.get(feat, '')
                
                if feat == 'proto':
                    features.append(self.PROTOCOL_MAP.get(value.lower(), -1))
                elif feat == 'service':
                    features.append(self.SERVICE_MAP.get(value.lower(), 0))
                elif feat == 'state':
                    features.append(self.STATE_MAP.get(value.upper(), 0))
            
            # Add engineered features
            sbytes = packet.get('sbytes', 0)
            dbytes = packet.get('dbytes', 0)
            features.extend([
                sbytes / (dbytes + 1e-6),  # bytes_ratio
                packet.get('sinpkt', 0) / (packet.get('dinpkt', 0) + 1e-6),  # packet_timing
                packet.get('sload', 0) / (packet.get('dload', 0) + 1e-6),  # load_ratio
                packet.get('swin', 0) / (packet.get('dwin', 0) + 1e-6),  # win_ratio
                abs(sbytes - dbytes),  # packet_size_diff
                sbytes + dbytes,  # packet_size_sum
                abs(packet.get('sjit', 0) - packet.get('djit', 0)),  # packet_jitter_diff
                abs(packet.get('sload', 0) - packet.get('dload', 0)),  # packet_load_diff
                packet.get('swin', 0) + packet.get('dwin', 0)  # packet_win_sum
            ])
            
            return np.array(features)
        except Exception as e:
            self.logger.error(f"Packet preprocessing error: {str(e)}")
            return np.zeros(len(self.all_feature_names))

    def _encode_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features in DataFrame"""
        df = df.copy()
        if 'proto' in df.columns:
            df['proto'] = df['proto'].str.lower().map(self.PROTOCOL_MAP).fillna(-1)
        if 'service' in df.columns:
            df['service'] = df['service'].str.lower().map(self.SERVICE_MAP).fillna(0)
        if 'state' in df.columns:
            df['state'] = df['state'].str.upper().map(self.STATE_MAP).fillna(0)
        return df

    def load_dataset(self, file_path: str) -> Optional[pd.DataFrame]:
        """Load and preprocess dataset from CSV file"""
        try:
            self.logger.info(f"Loading dataset: {os.path.basename(file_path)}")
            
            df = pd.read_csv(
                file_path,
                low_memory=False,
                na_values=[' ', '', 'NaN', 'N/A', 'na', 'none'],
                true_values=['yes', 'true', '1'],
                false_values=['no', 'false', '0']
            )
            
            # Clean and prepare dataset
            cols_to_drop = ['id', 'attack_cat', 'is_sm_ips_ports', 'ct_flw_http_mthd', 
                          'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src']
            df.drop(columns=[c for c in cols_to_drop if c in df.columns], inplace=True)
            
            # Encode categorical features
            df = self._encode_categorical(df)
            
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(0, inplace=True)
            
            # Convert all columns to numeric
            for col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            df.fillna(0, inplace=True)
            
            self.logger.info(f"Loaded dataset with shape: {df.shape}")
            return df
            
        except Exception as e:
            self.logger.error(f"Dataset loading failed: {str(e)}")
            return None

    def select_features(self, X: pd.DataFrame, y: np.ndarray, k: int = 20) -> np.ndarray:
        """Perform feature selection using ANOVA F-value"""
        try:
            self.logger.info(f"Selecting top {k} features...")
            
            self.selector = SelectKBest(score_func=f_classif, k=k)
            X_selected = self.selector.fit_transform(X, y)
            
            self.selected_features = X.columns[self.selector.get_support()].tolist()
            
            # Get indices of selected features in the full feature list
            self.selected_feature_indices = [
                i for i, feat in enumerate(self.all_feature_names)
                if feat in self.selected_features
            ]
            
            self.logger.info(f"Selected {len(self.selected_features)} features")
            return X_selected
        except Exception as e:
            self.logger.error(f"Feature selection failed: {str(e)}")
            return X.values

    def build_model(self, input_shape: Tuple, num_classes: int) -> Optional[Model]:
        """Construct the hybrid LSTM-Attention-CNN model architecture"""
        try:
            # Input layer
            inputs = Input(shape=input_shape)
            
            # Temporal feature extraction
            lstm_out = LSTM(128, return_sequences=True, dropout=0.2)(inputs)
            
            # Attention mechanism
            attention = Attention()([lstm_out, lstm_out])
            
            # Multi-scale feature extraction
            conv1 = Conv1D(64, kernel_size=3, activation='relu', padding='same')(attention)
            pool1 = GlobalMaxPooling1D()(conv1)
            
            conv2 = Conv1D(128, kernel_size=5, activation='relu', padding='same')(attention)
            pool2 = GlobalMaxPooling1D()(conv2)
            
            conv3 = Conv1D(256, kernel_size=7, activation='relu', padding='same')(attention)
            pool3 = GlobalMaxPooling1D()(conv3)
            
            # Feature fusion
            merged = Concatenate()([pool1, pool2, pool3])
            
            # Classification head
            x = Dense(256, activation='relu', kernel_regularizer='l2')(merged)
            x = BatchNormalization()(x)
            x = Dropout(0.4)(x)
            
            x = Dense(128, activation='relu', kernel_regularizer='l2')(x)
            x = BatchNormalization()(x)
            x = Dropout(0.3)(x)
            
            outputs = Dense(num_classes, activation='softmax')(x)
            
            # Create and compile model
            model = Model(inputs=inputs, outputs=outputs)
            model.compile(
                optimizer=Adam(learning_rate=0.0005),
                loss=self._focal_loss,
                metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
            )
            
            self.logger.info("Model built successfully")
            return model
            
        except Exception as e:
            self.logger.error(f"Model building failed: {str(e)}")
            return None

    def _create_sequences(self, data: np.ndarray, labels: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Create temporal sequences from packet data"""
        sequences = []
        sequence_labels = []
        
        for i in range(len(data) - self.SEQUENCE_LENGTH + 1):
            sequences.append(data[i:i+self.SEQUENCE_LENGTH])
            sequence_labels.append(labels[i+self.SEQUENCE_LENGTH-1])
            
        return np.array(sequences), np.array(sequence_labels)

    def _get_health_status(self, accuracy: float) -> str:
        """Determine model health based on accuracy score"""
        if accuracy >= 0.98:
            return 'excellent'
        elif accuracy >= 0.95:
            return 'very good'
        elif accuracy >= 0.90:
            return 'good'
        elif accuracy >= 0.85:
            return 'fair'
        return 'poor'

    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
        """Calculate evaluation metrics with error handling"""
        try:
            y_true = np.ravel(y_true).astype(int)
            y_pred = np.ravel(y_pred).astype(int)
            
            assert_all_finite(y_true)
            assert_all_finite(y_pred)
            
            return {
                'accuracy': float(accuracy_score(y_true, y_pred)),
                'precision': float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
                'recall': float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
                'f1_score': float(f1_score(y_true, y_pred, average='weighted', zero_division=0))
            }
        except Exception as e:
            self.logger.error(f"Metrics calculation failed: {str(e)}")
            return {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0
            }

    def train(self, 
             train_file: Optional[str] = None, 
             test_file: Optional[str] = None,
             epochs: int = 2,  # Increased default epochs
             batch_size: int = 512) -> bool:
        """Train the model with optional custom dataset paths"""
        try:
            start_time = time.time()
            
            # Load datasets
            train_path = self._get_dataset_path(train_file or "UNSW_NB15_training-set.csv")
            test_path = self._get_dataset_path(test_file or "UNSW_NB15_testing-set.csv")
            
            if not train_path or not test_path:
                self.logger.error("Required datasets not found")
                return False
                
            train_df = self.load_dataset(train_path)
            test_df = self.load_dataset(test_path)
            
            if train_df is None or test_df is None:
                return False
                
            # Prepare features and labels - NO COMBINING BEFORE FEATURE SELECTION
            X_train = train_df.drop(columns=['label'])
            y_train = train_df['label'].values
            
            X_test = test_df.drop(columns=['label'])
            y_test = test_df['label'].values
            
            # Encode labels
            self.encoder = LabelEncoder()
            y_train_encoded = self.encoder.fit_transform(y_train)
            y_test_encoded = self.encoder.transform(y_test)
            num_classes = len(self.encoder.classes_)
            
            # Feature selection and scaling - USE ONLY TRAINING DATA FOR FITTING
            X_train_selected = self.select_features(X_train, y_train_encoded)
            
            # Transform test data using selector fitted on training data
            X_test_selected = self.selector.transform(X_test)
            
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train_selected)
            X_test_scaled = self.scaler.transform(X_test_selected)
            
            # Create sequences
            X_train_seq, y_train_seq = self._create_sequences(X_train_scaled, y_train_encoded)
            X_test_seq, y_test_seq = self._create_sequences(X_test_scaled, y_test_encoded)
            
            # Build model
            input_shape = (self.SEQUENCE_LENGTH, X_train_seq.shape[2])
            self.model = self.build_model(input_shape, num_classes)
            
            if self.model is None:
                return False
                
            # Cross-validation training
            self.logger.info("Starting 5-fold cross-validation...")
            kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            cv_scores = {'accuracy': [], 'f1': []}
            
            for fold, (train_idx, val_idx) in enumerate(kfold.split(X_train_seq, y_train_seq), 1):
                self.logger.info(f"Training fold {fold}/5")
                
                X_fold_train, y_fold_train = X_train_seq[train_idx], y_train_seq[train_idx]
                X_fold_val, y_fold_val = X_train_seq[val_idx], y_train_seq[val_idx]
                
                y_fold_train_oh = to_categorical(y_fold_train, num_classes)
                y_fold_val_oh = to_categorical(y_fold_val, num_classes)
                
                history = self.model.fit(
                    X_fold_train, y_fold_train_oh,
                    validation_data=(X_fold_val, y_fold_val_oh),
                    epochs=epochs,
                    batch_size=batch_size,
                    verbose=1,
                    callbacks=[
                        EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True),
                        ModelCheckpoint(f"model_fold_{fold}.h5", save_best_only=True)
                    ]
                )
                
                y_pred = np.argmax(self.model.predict(X_fold_val, verbose=0), axis=1)
                cv_scores['accuracy'].append(accuracy_score(y_fold_val, y_pred))
                cv_scores['f1'].append(f1_score(y_fold_val, y_pred, average='weighted'))
                
                self.logger.info(f"Fold {fold} - Val Accuracy: {cv_scores['accuracy'][-1]:.4f}, F1: {cv_scores['f1'][-1]:.4f}")
            
            # Final training on full training dataset
            self.logger.info("Training on full dataset...")
            y_train_oh = to_categorical(y_train_seq, num_classes)
            
            history = self.model.fit(
                X_train_seq, y_train_oh,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.1,
                verbose=1,
                callbacks=[
                    EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)
                ]
            )
            
            # Evaluation on test set
            y_pred = np.argmax(self.model.predict(X_test_seq, verbose=0), axis=1)
            metrics = self._calculate_metrics(y_test_seq, y_pred)
            
            # Update model info
            self.model_info.update({
                'accuracy': metrics['accuracy'],
                'precision': metrics['precision'],
                'recall': metrics['recall'],
                'f1_score': metrics['f1_score'],
                'last_trained': int(time.time()),
                'training_time': int(time.time() - start_time),
                'health_status': self._get_health_status(metrics['accuracy']),
                'input_shape': input_shape,
                'cv_accuracy': float(np.mean(cv_scores['accuracy'])),
                'cv_f1': float(np.mean(cv_scores['f1']))
            })
            
            # Save model
            if not self._save_model():
                return False
                
            self.logger.info(f"Training complete. Test Accuracy: {metrics['accuracy']:.2%}, F1: {metrics['f1_score']:.2%}")
            return True
            
        except Exception as e:
            self.logger.error(f"Training failed: {str(e)}", exc_info=True)
            return False

    def analyze_packet(self, packet: Dict) -> Tuple[str, float]:
        """Analyze network packet for potential threats"""
        if not self.model or not self.scaler or not self.selector:
            return 'Normal', 0.0
            
        try:
            # Preprocess packet to get all features
            raw_features = self._preprocess_packet(packet)
            
            # Select only the features used during training
            if self.selected_feature_indices:
                processed_features = raw_features[self.selected_feature_indices]
            else:
                processed_features = raw_features
                
            # Add to sequence buffer
            self.sequence_buffer.append(processed_features)
            
            # Wait for complete sequence
            if len(self.sequence_buffer) < self.SEQUENCE_LENGTH:
                return 'Normal', 0.0
                
            # Create and scale sequence
            sequence = np.array([list(self.sequence_buffer)])
            scaled_seq = self.scaler.transform(sequence.reshape(-1, sequence.shape[-1]))
            scaled_seq = scaled_seq.reshape(sequence.shape)
            
            # Make prediction
            preds = self.model.predict(scaled_seq, verbose=0)
            class_idx = np.argmax(preds[0])
            confidence = float(np.max(preds[0]))
            
            # Get attack type
            attack_type = self.encoder.inverse_transform([class_idx])[0]
            
            return attack_type, confidence
            
        except Exception as e:
            self.logger.error(f"Packet analysis failed: {str(e)}")
            return 'Normal', 0.0

    def update_attack_stats(self, attack_type: str, source_ip: str) -> None:
        """Update attack statistics with new detection"""
        if attack_type == 'Normal':
            return
            
        now = time.time()
        self.attack_stats[attack_type]['count'] += 1
        self.attack_stats[attack_type]['last_seen'] = now
        
        if 'first_seen' not in self.attack_stats[attack_type]:
            self.attack_stats[attack_type]['first_seen'] = now
            
        # Add to real-time attacks
        self.realtime_attacks.append({
            'timestamp': now,
            'source_ip': source_ip,
            'attack_type': attack_type,
            'confidence': self.attack_stats[attack_type]['count'] / 
                         (now - self.attack_stats[attack_type]['first_seen'] + 1)
        })

    def get_attack_stats(self, time_window: int = 3600) -> Dict:
        """Get attack statistics for given time window (seconds)"""
        now = time.time()
        window_start = now - time_window
        
        stats = {
            'total': 0,
            'by_type': defaultdict(int),
            'recent': [],
            'start_time': window_start,
            'end_time': now
        }
        
        # Count attacks in time window
        for attack_type, data in self.attack_stats.items():
            if data['last_seen'] >= window_start:
                count = data['count'] if 'first_seen' in data and data['first_seen'] >= window_start else sum(
                    1 for attack in self.realtime_attacks 
                    if attack['timestamp'] >= window_start and attack['attack_type'] == attack_type
                )
                stats['by_type'][attack_type] = count
                stats['total'] += count
        
        # Get recent attacks
        stats['recent'] = [
            attack for attack in self.realtime_attacks
            if attack['timestamp'] >= window_start
        ][-10:]  # Last 10 attacks
        
        return stats

    def save_state(self, file_path: str) -> bool:
        """Save current model state to file"""
        state = {
            'model_info': self.model_info,
            'attack_stats': dict(self.attack_stats),
            'recent_attacks': list(self.realtime_attacks),
            'timestamp': time.time()
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(state, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save state: {str(e)}")
            return False

    def load_state(self, file_path: str) -> bool:
        """Load model state from file"""
        try:
            with open(file_path, 'r') as f:
                state = json.load(f)
                
            self.model_info = state.get('model_info', {})
            
            # Load attack stats
            self.attack_stats.clear()
            for k, v in state.get('attack_stats', {}).items():
                self.attack_stats[k] = v
                
            # Load recent attacks
            self.realtime_attacks.clear()
            self.realtime_attacks.extend(state.get('recent_attacks', []))
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to load state: {str(e)}")
            return False


if __name__ == "__main__":
    # Example usage
    ids = IDSModel()
    
    if ids.needs_training():
        logger.info("Model needs training - starting training process...")
        if ids.train(epochs=5):
            logger.info("Training completed successfully")
        else:
            logger.error("Training failed")
    
    # Test packet analysis
    test_packet = {
        'proto': 'tcp',
        'service': 'http',
        'state': 'SYN',
        'sbytes': 100,
        'dbytes': 0,
        'sttl': 64,
        'sload': 1000,
        'dload': 0,
        'sinpkt': 0.05,
        'dinpkt': 0,
        'sjit': 2,
        'djit': 0,
        'swin': 8192,
        'dwin': 0
    }
    
    # Analyze multiple packets to fill sequence buffer
    for _ in range(ids.SEQUENCE_LENGTH):
        attack_type, confidence = ids.analyze_packet(test_packet)
        ids.update_attack_stats(attack_type, "192.168.1.100")
    
    logger.info(f"Detection result: {attack_type} (confidence: {confidence:.2%})")
    
    # Get attack statistics
    stats = ids.get_attack_stats()
    logger.info(f"Attack stats (last hour): {stats['total']} attacks")