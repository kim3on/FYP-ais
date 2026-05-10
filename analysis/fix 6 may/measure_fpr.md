# Plan: Expose False Positive Rate (FPR)

## Objective
Expose the False Positive Rate (FPR) - representing the percentage of normal traffic incorrectly flagged as an attack - on the frontend dashboard and training pages, utilizing the existing calculation from the backend evaluator.

## 1. Backend Verification
- Ensure that `app/core/evaluator.py` correctly calculates and returns `false_positive_rate` within the `EvaluationResult` dataclass. (Currently implemented as `fp / (fp + tn)`).

## 2. Frontend Updates
Update the React frontend components to display the FPR alongside existing metrics (Accuracy, Precision, Recall, F1 Score). Convert the float value to a percentage (e.g., `(result.false_positive_rate * 100).toFixed(1)%`).

### Target Files:
1. `frontend/src/pages/Training.jsx`
   - In the "Training Result" grid, add a new row/item: `['False Pos. Rate', result.false_positive_rate != null ? ${ (result.false_positive_rate * 100).toFixed(1) }% : '—']`.
2. `frontend/src/pages/TrainDetect.jsx`
   - In the results mapping array, add `['False Pos. Rate', result.false_positive_rate]`.
3. `frontend/src/pages/Detection.jsx`
   - Add `['FPR', result.false_positive_rate]` to the metrics array displayed when `result.accuracy != null`.

## Verification
- Run a training or detection pipeline via the UI.
- Verify that the "False Pos. Rate" appears correctly formatted as a percentage in the metrics grid.