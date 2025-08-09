import pytest
import uuid

from app.models.calculation import (
    Calculation,
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Modulus,
    IntDivision,
)

# Helper function to create a dummy user_id for testing.
def dummy_user_id():
    return uuid.uuid4()

def test_addition_get_result():
    """
    Test that Addition.get_result returns the correct sum.
    """
    inputs = [10, 5, 3.5]
    addition = Addition(user_id=dummy_user_id(), inputs=inputs)
    result = addition.get_result()
    assert result == sum(inputs), f"Expected {sum(inputs)}, got {result}"

def test_subtraction_get_result():
    """
    Test that Subtraction.get_result returns the correct difference.
    """
    inputs = [20, 5, 3]
    subtraction = Subtraction(user_id=dummy_user_id(), inputs=inputs)
    # Expected: 20 - 5 - 3 = 12
    result = subtraction.get_result()
    assert result == 12, f"Expected 12, got {result}"

def test_multiplication_get_result():
    """
    Test that Multiplication.get_result returns the correct product.
    """
    inputs = [2, 3, 4]
    multiplication = Multiplication(user_id=dummy_user_id(), inputs=inputs)
    result = multiplication.get_result()
    assert result == 24, f"Expected 24, got {result}"

def test_division_get_result():
    """
    Test that Division.get_result returns the correct quotient.
    """
    inputs = [100, 2, 5]
    division = Division(user_id=dummy_user_id(), inputs=inputs)
    # Expected: 100 / 2 / 5 = 10
    result = division.get_result()
    assert result == 10, f"Expected 10, got {result}"

def test_division_by_zero():
    """
    Test that Division.get_result raises ValueError when dividing by zero.
    """
    inputs = [50, 0, 5]
    division = Division(user_id=dummy_user_id(), inputs=inputs)
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        division.get_result()

def test_modulus_get_result():
    """
    Test that Modulus.get_result returns the correct quotient.
    """
    inputs = [100, 27, 5]
    modulus = Modulus(user_id=dummy_user_id(), inputs=inputs)
    # Expected: 100 % 27 % 5 = 4
    result = modulus.get_result()
    assert result == 4, f"Expected 4, got {result}"

def test_modulus_by_zero():
    """
    Test that Division.get_result raises ValueError when dividing by zero.
    """
    inputs = [50, 0, 5]
    modulus = Modulus(user_id=dummy_user_id(), inputs=inputs)
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        modulus.get_result()

def test_intdivision_get_result():
    """
    Test that IntDivision.get_result returns the correct quotient.
    """
    inputs = [100, 7, 5]
    division = IntDivision(user_id=dummy_user_id(), inputs=inputs)
    # Expected: 100 // 7 // 5 = 2
    result = division.get_result()
    assert result == 2, f"Expected 2, got {result}"

def test_intdivision_by_zero():
    """
    Test that Division.get_result raises ValueError when dividing by zero.
    """
    inputs = [50, 0, 5]
    division = IntDivision(user_id=dummy_user_id(), inputs=inputs)
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        division.get_result()

def test_calculation_factory_addition():
    """
    Test the Calculation.create factory method for addition.
    """
    inputs = [1, 2, 3]
    calc = Calculation.create(
        calculation_type='addition',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Check that the returned instance is an Addition.
    assert isinstance(calc, Addition), "Factory did not return an Addition instance."
    assert calc.get_result() == sum(inputs), "Incorrect addition result."

def test_calculation_factory_subtraction():
    """
    Test the Calculation.create factory method for subtraction.
    """
    inputs = [10, 4]
    calc = Calculation.create(
        calculation_type='subtraction',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 10 - 4 = 6
    assert isinstance(calc, Subtraction), "Factory did not return a Subtraction instance."
    assert calc.get_result() == 6, "Incorrect subtraction result."

def test_calculation_factory_multiplication():
    """
    Test the Calculation.create factory method for multiplication.
    """
    inputs = [3, 4, 2]
    calc = Calculation.create(
        calculation_type='multiplication',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 3 * 4 * 2 = 24
    assert isinstance(calc, Multiplication), "Factory did not return a Multiplication instance."
    assert calc.get_result() == 24, "Incorrect multiplication result."

def test_calculation_factory_division():
    """
    Test the Calculation.create factory method for division.
    """
    inputs = [100, 2, 5]
    calc = Calculation.create(
        calculation_type='division',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 100 / 2 / 5 = 10
    assert isinstance(calc, Division), "Factory did not return a Division instance."
    assert calc.get_result() == 10, "Incorrect division result."

def test_calculation_factory_modulus():
    """
    Test the Calculation.create factory method for modulus.
    """
    inputs = [100, 27, 5]
    calc = Calculation.create(
        calculation_type='modulus',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 100 % 27 % 5 = 4
    assert isinstance(calc, Modulus), "Factory did not return a Modulus instance."
    assert calc.get_result() == 4, "Incorrect modulus result."

def test_calculation_factory_intdivision():
    """
    Test the Calculation.create factory method for integer division.
    """
    inputs = [100, 7, 5]
    calc = Calculation.create(
        calculation_type='intdivision',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 100 / 7 / 5 = 2
    assert isinstance(calc, IntDivision), "Factory did not return an IntDivision instance."
    assert calc.get_result() == 2, "Incorrect integer division result."

def test_calculation_factory_invalid_type():
    """
    Test that Calculation.create raises a ValueError for an unsupported calculation type.
    """
    with pytest.raises(ValueError, match="Unsupported calculation type"):
        Calculation.create(
            calculation_type='invalidtype',  # unsupported type
            user_id=dummy_user_id(),
            inputs=[10, 3],
        )

def test_invalid_inputs_for_addition():
    """
    Test that providing non-list inputs to Addition.get_result raises a ValueError.
    Test that providing fewer than two numbers to Addition.get_result raises a ValueError.
    """
    addition = Addition(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        addition.get_result()

    addition = Addition(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        addition.get_result()


def test_invalid_inputs_for_subtraction():
    """
    Test that providing non-list inputs to Subtraction.get_result raises a ValueError.
    Test that providing fewer than two numbers to Subtraction.get_result raises a ValueError.
    """
    subtraction = Subtraction(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        subtraction.get_result()

    subtraction = Subtraction(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        subtraction.get_result()

def test_invalid_inputs_for_multiplication():
    """
    Test that providing non-list inputs to Multiplication.get_result raises a ValueError.
    Test that providing fewer than two numbers to Multiplication.get_result raises a ValueError.
    """
    multiplication = Multiplication(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        multiplication.get_result()

    multiplication = Multiplication(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        multiplication.get_result()

def test_invalid_inputs_for_division():
    """
    Test that providing non-list inputs to Division.get_result raises a ValueError.
    Test that providing fewer than two numbers to Division.get_result raises a ValueError.
    Test that providing 0 after first value to Division.get_result raises a ValueError.
    """
    division = Division(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        division.get_result()

    division = Division(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        division.get_result()

    division = Division(user_id=dummy_user_id(), inputs=[10, 2, 0])
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        division.get_result()


def test_invalid_inputs_for_modulus():
    """
    Test that providing non-list inputs to Modulus.get_result raises a ValueError.
    Test that providing fewer than two numbers to Modulus.get_result raises a ValueError.
    Test that providing 0 after first value to Modulus.get_result raises a ValueError.
    """
    modulus = Modulus(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        modulus.get_result()

    modulus = Modulus(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        modulus.get_result()

    modulus = Modulus(user_id=dummy_user_id(), inputs=[10, 2, 0])
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        modulus.get_result()

def test_invalid_inputs_for_intdivision():
    """
    Test that providing non-list inputs to IntDivision.get_result raises a ValueError.
    Test that providing fewer than two numbers to IntDivision.get_result raises a ValueError.
    Test that providing 0 after first value to IntDivision.get_result raises a ValueError.
    """
    intdivision = IntDivision(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        intdivision.get_result()

    intdivision = IntDivision(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        intdivision.get_result()

    intdivision = IntDivision(user_id=dummy_user_id(), inputs=[10, 2, 0])
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        intdivision.get_result()
