import { useState } from 'react';
import '../components/Layout/Layout.css';
import './TrainDetect.css';
import DetectionTab from './train-detect/DetectionTab';
import GlobalTrainingResult from './train-detect/GlobalTrainingResult';
import TrainingTab from './train-detect/TrainingTab';


// ══════════════════════════════════════════════════════════════
//  MAIN PAGE — Tab switcher
// ══════════════════════════════════════════════════════════════
export default function TrainDetect() {
  const [tab, setTab] = useState('train');
  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Train & Detect</h1>
        <p className="page-subtitle">Train an unsupervised NSA self profile · Run batch anomaly detection</p>
      </div>

      <GlobalTrainingResult />

      {/* Tab bar */}
      <div className="td-tabs">
        <button className={`td-tab ${tab === 'train' ? 'active' : ''}`} onClick={() => setTab('train')}>
          <span>⚙</span> Training
        </button>
        <button className={`td-tab ${tab === 'detect' ? 'active' : ''}`} onClick={() => setTab('detect')}>
          <span>⬢</span> Detection
        </button>
      </div>

      {tab === 'train'  && <TrainingTab />}
      {tab === 'detect' && <DetectionTab />}
    </div>
  );
}
