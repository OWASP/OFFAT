# Routeless module: the sink here is reachable from no mapped endpoint, so the
# gray-box pipeline should mark it unreachable and cap its verdict.
import pickle


def load_blob(data):
    return pickle.loads(data)  # unsafe deserialization, not reachable from a route
