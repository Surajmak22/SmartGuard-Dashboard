import tensorflow as tf
import tensorflow_model_optimization as tfmot
import numpy as np
import os

def prune_cnn(model, X_train, y_train):
    """
    Applies weight pruning to the CNN model.
    """
    pruning_params = {
        'pruning_schedule': tfmot.sparsity.keras.PolynomialDecay(
            initial_sparsity=0.0,
            final_sparsity=0.5,
            begin_step=0,
            end_step=1000
        )
    }
    
    pruned_model = tfmot.sparsity.keras.prune_low_magnitude(model, **pruning_params)
    
    # Recompile and train briefly to apply pruning
    pruned_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    callbacks = [tfmot.sparsity.keras.UpdatePruningStep()]
    pruned_model.fit(X_train, y_train, epochs=2, callbacks=callbacks, verbose=0)
    
    return tfmot.sparsity.keras.strip_pruning(pruned_model)

def quantize_and_save_tflite(keras_model, output_path):
    """
    Applies post-training quantization and saves as TFLite.
    """
    converter = tf.lite.TFLiteConverter.from_keras_model(keras_model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()
    
    with open(output_path, 'wb') as f:
        f.write(tflite_model)
    
    return os.path.getsize(output_path)

def benchmark_tflite(tflite_path, X_test):
    """
    Benchmarks inference latency for TFLite model.
    """
    import time
    
    interpreter = tf.lite.Interpreter(model_path=tflite_path)
    interpreter.allocate_tensors()
    
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    latencies = []
    for i in range(min(100, len(X_test))):
        input_data = np.expand_dims(X_test[i], axis=0).astype(np.float32)
        if len(input_data.shape) == 2:
            input_data = np.expand_dims(input_data, axis=-1)
            
        interpreter.set_tensor(input_details[0]['index'], input_data)
        
        start_time = time.time()
        interpreter.invoke()
        latencies.append(time.time() - start_time)
        
    return np.mean(latencies), np.std(latencies)
