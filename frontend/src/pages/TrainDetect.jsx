import { useState } from 'react';
import '../components/Layout/Layout.css';
import './TrainDetect.css';
import DetectionTab from './train-detect/DetectionTab';
import GlobalTrainingResult from './train-detect/GlobalTrainingResult';
import TrainingTab from './train-detect/TrainingTab';
import { useAuth } from '../hooks/useAuth';


// ══════════════════════════════════════════════════════════════
//  MAIN PAGE — Tab switcher
// ══════════════════════════════════════════════════════════════
export default function TrainDetect() {
  const [tab, setTab] = useState('train');
  const { currentUser } = useAuth();
  const role = (currentUser?.role || '').toLowerCase();
  const canOperate = role.includes('administrator') || role === 'admin';

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Train & Detect</h1>
        <p className="page-subtitle">Train unsupervised NSA and Isolation Forest profiles · Run batch anomaly detection</p>
      </div>

      <GlobalTrainingResult />
      {!canOperate && (
        <div className="td-access-note">
          Administrator access is required!
        </div>
      )}

      {/* Tab bar */}
      <div className="td-tabs">
        <button className={`td-tab ${tab === 'train' ? 'active' : ''}`} onClick={() => setTab('train')}>
          <span>⚙</span> Training
        </button>
        <button className={`td-tab ${tab === 'detect' ? 'active' : ''}`} onClick={() => setTab('detect')}>
          <span>⬢</span> Detection
        </button>
      </div>

      {tab === 'train'  && <TrainingTab canOperate={canOperate} />}
      {tab === 'detect' && <DetectionTab canOperate={canOperate} />}
    </div>
  );
}
