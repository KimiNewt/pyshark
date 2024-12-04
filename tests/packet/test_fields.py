import pytest

from pyshark.packet.fields import LayerField, LayerFieldsContainer

# Unit Tests - Layer Fields
def test_layer_field_hide():
    hide_yes = LayerField(hide="yes")
    hide_not_yes = LayerField(hide="not yes")
    assert hide_yes.hide == True and hide_not_yes.hide == False

def test_layer_field_print_format():
    name = "test_name"
    show = "test"
    test_layer_field = LayerField(name=name, show=show)
    str_layer_field = test_layer_field.__repr__()
    assert str_layer_field == f'<LayerField {name}: {show}>'

def test_layer_field_default_value_show():
    show = "test"
    test_layer_field = LayerField(show=show)
    default_value = test_layer_field.get_default_value()
    assert default_value == show

def test_layer_field_default_value_value():
    value = "test"
    test_layer_field = LayerField(value=value)
    default_value = test_layer_field.get_default_value()
    assert default_value == value

def test_layer_field_default_value_showname():
    showname = "test"
    test_layer_field = LayerField(showname=showname)
    default_value = test_layer_field.get_default_value()
    assert default_value == showname

def test_layer_field_showname_value():
    value = "test_value"
    showname = f"test: {value}"
    test_layer_field = LayerField(showname=showname)
    assert value == test_layer_field.showname_value

def test_layer_field_showname_key():
    key = "test_key"
    showname = f"{key}: value"
    test_layer_field = LayerField(showname=showname)
    assert key == test_layer_field.showname_key

def test_layer_field_showname_binary():
    binary = b"\x124"
    test_layer_field = LayerField(value="1234")
    assert binary == test_layer_field.binary_value

def test_layer_field_str_int_value():
    str_int_value = "10"
    int_value = 10
    test_layer_field = LayerField(value=str_int_value)
    assert test_layer_field.int_value == int_value

def test_layer_field_hex_value():
    test_int_value = "0x75BCD15"
    expected_value = 123456789
    test_layer_field = LayerField(value=test_int_value)
    asserttest_layer_field.hex_value == expected_value

# Test Data - Layer Fields Container
test_layer_field = LayerField(name="test_field", value={"test": "value"})

@pytest.fixture
def layer_fields_container():
    return LayerFieldsContainer(test_layer_field)

# Unit Tests - Layer Fields Container
def test_layer_fields_container_adds_single_field(layer_fields_container):
    new_field = LayerField(name="new_field", value={"new_test": "new_test_value"})
    layer_fields_container.add_field(new_field)
    fields = layer_fields_container.all_fields
    assert fields == [test_layer_field, new_field]

def test_layer_fields_container_returns_all_fields(layer_fields_container):
    fields = layer_fields_container.all_fields
    assert fields == [test_layer_field]

def test_layer_fields_container_gets_main_field(layer_fields_container):
    main_field = layer_fields_container.main_field
    assert main_field == test_layer_field

def test_layer_fields_container_gets_alternate_fields(layer_fields_container):
    alternate_field_1 = LayerField(name="alt_field_1", value={"alt_field_1": "alt_value_1"})
    alternate_field_2 = LayerField(name="alt_field_2", value={"alt_field_2": "alt_value_2"})
    layer_fields_container.add_field(alternate_field_1)
    layer_fields_container.add_field(alternate_field_2)
    alternate_fields = layer_fields_container.alternate_fields
    assert alternate_fields == [alternate_field_1, alternate_field_2]
