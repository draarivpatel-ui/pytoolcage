import unittest

from pytoolcage import inspect_tool_arguments, validate_tool_arguments
from helpers import add_case


def validate(args, parameters, extra=None):
    spec = {"parameters": parameters}
    if extra:
        spec.update(extra)
    return validate_tool_arguments(args, spec)


def expect_code(case, result, code):
    case.assertFalse(result["ok"])
    case.assertIn(code, [item["code"] for item in result.get("errors", [])])


class TestSchemaMatrix(unittest.TestCase):
    pass


valid_cases = [
    ("string", "hello"), ("string", ""), ("number", 0), ("number", -12.5),
    ("integer", 0), ("integer", -10), ("boolean", True), ("boolean", False),
    ("path", "safe/file.txt"), ("url", "https://example.com/a"), ("command", "git status"),
    ("any", "text"), ("any", 42), ("any", False), ("null", None),
]
for index, (kind, value) in enumerate(valid_cases):
    def check(self, kind=kind, value=value):
        result = validate({"value": value}, {"value": {"type": kind, "required": True}})
        self.assertTrue(result["ok"], result.get("errors"))
        self.assertEqual(result["normalizedArguments"]["value"], value)
    add_case(TestSchemaMatrix, "valid_%s_%d" % (kind, index), check)

invalid_cases = [
    ("string", 1), ("string", True), ("number", "1"), ("number", float("nan")),
    ("number", float("inf")), ("integer", 1.5), ("integer", True), ("boolean", "true"),
    ("boolean", 1), ("path", 12), ("url", False), ("command", []), ("null", "null"),
]
for index, (kind, value) in enumerate(invalid_cases):
    def check(self, kind=kind, value=value):
        self.assertFalse(validate({"value": value}, {"value": {"type": kind, "required": True}})["ok"])
    add_case(TestSchemaMatrix, "invalid_%s_%d" % (kind, index), check)

for value in range(11):
    def check(self, value=value):
        self.assertTrue(validate({"value": value}, {"value": {"type": "integer", "min": 0, "max": 10}})["ok"])
    add_case(TestSchemaMatrix, "range_accepts_%d" % value, check)
for value in (-10, -1, 11, 100):
    def check(self, value=value):
        expect_code(self, validate({"value": value}, {"value": {"type": "integer", "min": 0, "max": 10}}), "NUMBER_TOO_SMALL" if value < 0 else "NUMBER_TOO_LARGE")
    add_case(TestSchemaMatrix, "range_rejects_%s" % str(value).replace("-", "minus"), check)

for value in (2, 4, 10, -6):
    def check(self, value=value):
        self.assertTrue(validate({"value": value}, {"value": {"type": "integer", "multipleOf": 2}})["ok"])
    add_case(TestSchemaMatrix, "multiple_accepts_%s" % value, check)
for value in (1, 3, 5, 7, 9, 11, -3):
    def check(self, value=value):
        expect_code(self, validate({"value": value}, {"value": {"type": "integer", "multipleOf": 2}}), "NUMBER_MULTIPLE_MISMATCH")
    add_case(TestSchemaMatrix, "multiple_rejects_%s" % value, check)

string_cases = [
    ("empty", "", 0, 3, True), ("one", "a", 0, 3, True), ("max", "abc", 0, 3, True),
    ("too_long", "abcd", 0, 3, False), ("too_short", "a", 2, 4, False), ("min", "ab", 2, 4, True),
    ("unicode_ok", "a\u20acb", 2, 3, True), ("unicode_long", "a\u20acb\u20ac", 2, 3, False),
]
for name, value, minimum, maximum, ok in string_cases:
    def check(self, value=value, minimum=minimum, maximum=maximum, ok=ok):
        self.assertEqual(validate({"value": value}, {"value": {"type": "string", "minLength": minimum, "maxLength": maximum}})["ok"], ok)
    add_case(TestSchemaMatrix, "string_length_" + name, check)

pattern_cases = [
    ("lower_ok", "^[a-z]+$", "abc", True), ("lower_bad", "^[a-z]+$", "Abc", False),
    ("digits_ok", "^\\d{2,4}$", "123", True), ("digits_bad", "^\\d{2,4}$", "12a", False),
    ("unicode_ok", "^[^\\s]+$", "caf\u00e9", True), ("anchor_bad", "^ok$", "nook", False),
]
for name, pattern, value, ok in pattern_cases:
    def check(self, pattern=pattern, value=value, ok=ok):
        self.assertEqual(validate({"value": value}, {"value": {"type": "string", "pattern": pattern}})["ok"], ok)
    add_case(TestSchemaMatrix, "pattern_" + name, check)

enum_cases = [
    ("string", ["a", "b"], "a", True), ("string_bad", ["a", "b"], "c", False),
    ("number", [1, 2], 2, True), ("boolean", [True], True, True), ("null", [None], None, True),
    ("object", [{"a": 1}], {"a": 1}, True), ("object_order", [{"a": 1, "b": 2}], {"b": 2, "a": 1}, True),
    ("array", [[1, 2]], [1, 2], True), ("array_order", [[1, 2]], [2, 1], False),
]
for name, options, value, ok in enum_cases:
    def check(self, options=options, value=value, ok=ok):
        self.assertEqual(validate({"value": value}, {"value": {"type": "any", "enum": options}})["ok"], ok)
    add_case(TestSchemaMatrix, "enum_" + name, check)

array_cases = [
    ("empty", [], 0, 2, True), ("one", [1], 1, 2, True), ("max", [1, 2], 1, 2, True),
    ("too_long", [1, 2, 3], 1, 2, False), ("too_short", [], 1, 2, False),
]
for name, value, minimum, maximum, ok in array_cases:
    def check(self, value=value, minimum=minimum, maximum=maximum, ok=ok):
        self.assertEqual(validate({"value": value}, {"value": {"type": "array", "minItems": minimum, "maxItems": maximum}})["ok"], ok)
    add_case(TestSchemaMatrix, "array_length_" + name, check)

unique_cases = [
    ("unique", [1, 2, 3], True), ("dupe_number", [1, 2, 1], False),
    ("unique_objects", [{"a": 1}, {"a": 2}], True), ("dupe_object", [{"a": 1, "b": 2}, {"b": 2, "a": 1}], False),
    ("dupe_array", [[1], [1]], False), ("null_false", [None, False], True),
]
for name, value, ok in unique_cases:
    def check(self, value=value, ok=ok):
        self.assertEqual(validate({"value": value}, {"value": {"type": "array", "uniqueItems": True}})["ok"], ok)
    add_case(TestSchemaMatrix, "array_unique_" + name, check)

item_cases = [
    ("valid", [1, 2], {"type": "integer"}, True, None),
    ("bad_type", [1, "x"], {"type": "integer"}, False, "TYPE_MISMATCH"),
    ("nested_valid", [{"name": "a"}], {"type": "object", "properties": {"name": {"type": "string", "required": True}}}, True, None),
    ("nested_missing", [{}], {"type": "object", "properties": {"name": {"type": "string", "required": True}}}, False, "REQUIRED_ARGUMENT_MISSING"),
    ("nested_unknown", [{"name": "a", "extra": 1}], {"type": "object", "properties": {"name": {"type": "string"}}}, False, "UNKNOWN_ARGUMENT_KEY"),
]
for name, value, item_spec, ok, code in item_cases:
    def check(self, value=value, item_spec=item_spec, ok=ok, code=code):
        result = validate({"value": value}, {"value": {"type": "array", "items": item_spec}})
        self.assertEqual(result["ok"], ok, result.get("errors"))
        if code:
            expect_code(self, result, code)
    add_case(TestSchemaMatrix, "array_items_" + name, check)

object_cases = [
    ("empty", {}, {"type": "object", "properties": {}}, True, None),
    ("known", {"name": "x"}, {"type": "object", "properties": {"name": {"type": "string"}}}, True, None),
    ("unknown", {"extra": 1}, {"type": "object", "properties": {}}, False, "UNKNOWN_ARGUMENT_KEY"),
    ("additional", {"extra": 1}, {"type": "object", "additionalProperties": True}, True, None),
    ("missing", {}, {"type": "object", "properties": {"name": {"type": "string", "required": True}}}, False, "REQUIRED_ARGUMENT_MISSING"),
    ("too_many", {"a": 1, "b": 2}, {"type": "object", "additionalProperties": True, "maxProperties": 1}, False, "OBJECT_TOO_MANY_PROPERTIES"),
]
for name, value, object_spec, ok, code in object_cases:
    def check(self, value=value, object_spec=object_spec, ok=ok, code=code):
        result = validate({"value": value}, {"value": object_spec})
        self.assertEqual(result["ok"], ok, result.get("errors"))
        if code:
            expect_code(self, result, code)
    add_case(TestSchemaMatrix, "object_" + name, check)

structural_cases = [
    ("unknown_top", {"known": "x", "extra": 1}, {"known": {"type": "string"}}, "UNKNOWN_ARGUMENT_KEY"),
    ("missing_required", {}, {"known": {"type": "string", "required": True}}, "REQUIRED_ARGUMENT_MISSING"),
    ("null_rejected", {"value": None}, {"value": {"type": "string"}}, "TYPE_MISMATCH"),
]
for name, args, parameters, code in structural_cases:
    def check(self, args=args, parameters=parameters, code=code):
        expect_code(self, validate(args, parameters), code)
    add_case(TestSchemaMatrix, "structure_" + name, check)

for key in ("__proto__", "constructor", "prototype", "__class__", "__dict__"):
    def check(self, key=key):
        expect_code(self, inspect_tool_arguments({key: 1}), "PROTOTYPE_POLLUTION_KEY")
    add_case(TestSchemaMatrix, "dangerous_key_" + key, check)

for name, value in [("tuple", (1,)), ("set", {1}), ("object", object()), ("bytes", b"x"), ("nan", float("nan")), ("inf", float("inf"))]:
    def check(self, value=value):
        self.assertFalse(inspect_tool_arguments({"value": value})["ok"])
    add_case(TestSchemaMatrix, "unsupported_" + name, check)

def make_depth(value, depth):
    output = value
    for _ in range(depth):
        output = {"child": output}
    return output

for depth in (0, 1, 4, 8, 12):
    def check(self, depth=depth):
        self.assertTrue(validate({"value": make_depth("x", depth)}, {"value": {"type": "any"}})["ok"])
    add_case(TestSchemaMatrix, "depth_accepts_%d" % depth, check)
for depth in (13, 14, 20):
    def check(self, depth=depth):
        expect_code(self, validate({"value": make_depth("x", depth)}, {"value": {"type": "any"}}), "DEPTH_EXCEEDED")
    add_case(TestSchemaMatrix, "depth_rejects_%d" % depth, check)
for limit, depth, ok in ((0, 0, True), (1, 1, True), (1, 2, False), (4, 3, True), (4, 5, False)):
    def check(self, limit=limit, depth=depth, ok=ok):
        self.assertEqual(validate({"value": make_depth("x", depth)}, {"value": {"type": "any"}}, {"maxDepth": limit})["ok"], ok)
    add_case(TestSchemaMatrix, "depth_limit_%d_depth_%d" % (limit, depth), check)

for limit, size, ok in ((10, 4, False), (20, 4, True), (30, 4, True), (1000, 200, True), (40, 200, False)):
    def check(self, limit=limit, size=size, ok=ok):
        self.assertEqual(validate({"value": "x" * size}, {"value": {"type": "string"}}, {"maxBytes": limit})["ok"], ok)
    add_case(TestSchemaMatrix, "bytes_%d_size_%d" % (limit, size), check)


class TestSchemaSingles(unittest.TestCase):
    def test_optional_key_absent(self):
        self.assertTrue(validate({}, {"known": {"type": "string"}})["ok"])

    def test_null_nullable(self):
        self.assertTrue(validate({"value": None}, {"value": {"type": "string", "nullable": True}})["ok"])

    def test_cycle_rejected(self):
        value = {}
        value["self"] = value
        self.assertFalse(inspect_tool_arguments(value)["ok"])

    def test_non_string_key_rejected(self):
        self.assertFalse(inspect_tool_arguments({1: "x"})["ok"])

    def test_arguments_must_be_dict(self):
        self.assertFalse(inspect_tool_arguments([])["ok"])

    def test_normalized_detached(self):
        source = {"value": {"nested": "x"}}
        result = validate(source, {"value": {"type": "object", "additionalProperties": True}})
        source["value"]["nested"] = "changed"
        self.assertEqual(result["normalizedArguments"]["value"]["nested"], "x")

    def test_measurement_reported(self):
        result = validate({"value": "x"}, {"value": {"type": "string"}})
        self.assertGreater(result["bytes"], 0)
        self.assertEqual(result["depth"], 0)

    def test_invalid_type(self):
        expect_code(self, validate({"value": 1}, {"value": {"type": "mystery"}}), "INVALID_POLICY_TYPE")

    def test_invalid_pattern(self):
        expect_code(self, validate({"value": "x"}, {"value": {"type": "string", "pattern": "["}}), "INVALID_POLICY_PATTERN")

    def test_path_delegate(self):
        self.assertFalse(validate({"value": "../x"}, {"value": {"type": "path"}})["ok"])
        self.assertTrue(validate({"value": "safe.txt"}, {"value": {"type": "path"}})["ok"])


if __name__ == "__main__":
    unittest.main()
