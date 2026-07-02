# ML deployment artifacts

- 'model.pkl' is the complete trained pipeline and metadata bundle.
- 'scaler.pkl' is the fitted scaler extracted from the pipeline.
- 'encoder.pkl' contains the supported detection-category label encoder.

Regenerate the bundle with 'python train_model.py' when using a production
dataset. Keep preprocessing artifacts and the model from the same training run.
