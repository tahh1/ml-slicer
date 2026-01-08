# ml-slicer

`ml-slicer` is a Python package that implements a **static backward slicing pipeline for machine learning code**, designed to extract focused, semantically meaningful code slices around _train/test model pairs_.

This repository represents an **engineering extension and re-architecture** of prior static data-flow analysis work into a practical, reusable slicing system.

### Why this project exists

ML pipeline slices can be fed to downstream classification tasks where compact non-noisy input improves model outputs.

Machine learning notebooks often mix:

- data preprocessing
- feature engineering
- model training
- evaluation
- experimentation logic

Instead of feeding entire notebooks to classifiers, `ml-slicer` produces **backward program slices** anchored at concrete _train/test model pairs_, capturing **only the code that can influence model behavior**.

The output slices are:

- minimal but sufficient
- deterministic
- text-based

### High-level pipeline

1. Model & model-pair detection
2. Static analysis (data-flow + control-flow)
3. Backward reachability slicing
4. Subgraph extraction
5. Code snippet extraction

Each slice corresponds to a specific `(train model, test model)` pair and represents all code that can influence that pair.

### Model and model-pair detection

The slicer identifies model anchors using **two complementary strategies**:

#### 1. Pattern-based model detection

Models are detected using known syntactic and semantic patterns, such as:

- `.fit(...)` calls
- common estimator APIs

At the same time, the system **explicitly filters out non-model constructs**, including:

- preprocessing pipelines
- transformers
- encoders and utility components

This avoids anchoring slices on irrelevant code.

#### 2. PyTorch model detection via type inference

Pattern matching alone is insufficient for PyTorch models.

To address this, `ml-slicer` integrates **PyWrite**, a Node-based static type inference engine:

- Pyright performs whole-program type inference
- Subtype predicates are used to determine whether objects are subtypes of `torch.nn.Module`
- This enables reliable identification of PyTorch models, even under dynamic construction patterns

Pyright is executed externally via Node, and its inferred type information is fed back into the slicing pipeline.

This project builds on ideas from prior static leakage detection work, most notably:

**Data Leakage in Notebooks: Static Detection and Better Processes**  
ASE 2022  
https://www.cs.cmu.edu/~cyang3/papers/ase22.pdf  
https://github.com/malusamayo/leakage-analysis

The original system focuses on **data-flow analysis** to detect leakage patterns.

`ml-slicer` extends this foundation by:

- adding **control-flow awareness**
- performing **backward reachability analysis**
- constructing **induced subgraphs** around model pairs
- exporting **program slices**, not just reports

#### Output:

Each slice is:

- anchored at a concrete train/test model pair
- backward-only (captures influencing context)
- isolated from unrelated notebook code
- exported as structured, textual artifacts

## Installation

#### Python version

- **Python 3.8.x** (currently tested and supported)

#### External tools (must be available on PATH)

- `souffle` (Datalog engine)
- `node` (for Pyright)

#### Install (development / editable)

```bash
python3.8 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```python
from mlslicer import run_slicer

run_slicer(
    input_path="path/to/input_file",
    output_dir="path/to/output_dir",
    verbose=True,
)
```

- All outputs are written to `output_dir`
- The package never writes inside its own installation directory
- Logging is quiet by default unless `verbose=True`

## Project structure

```text
ml-slicer/
├── src/
│   └── mlslicer/
│       ├── __init__.py
│       ├── api.py
│       ├── main.py
│       ├── config.py
│       ├── datalog/
│       │   └── main.dl
│       └── tools/
│           └── pyright/
│               └── ...
├── pyproject.toml
├── README.md
```
