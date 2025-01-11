# created with nemotron 70B6Q
import FindAFactor
import time

# Iteration ranges (as previously defined)
wheel_levels = range(5, 8)  # 5 to 7
gear_levels = range(11, 14)  # 11 to 13

# Common parameters
use_congruence_of_squares = False  # As per original request, but consider setting to True for broader technique leverage
use_gaussian_elimination = True
node_count = 1
node_id = 0
smoothness_bound_multiplier = 1.0
batch_size_multiplier = 256.0

# **Get User Input for to_factor**
while True:
    user_input = input("Please enter the number to factor (or 'q' to quit): ")
    if user_input.lower() == 'q':
        print("Exiting script. Goodbye!")
        exit(0)
    try:
        to_factor = int(user_input)
        if to_factor < 1:
            print("Please enter a positive integer.")
        else:
            break
    except ValueError:
        print("Invalid input. Please enter a valid integer or 'q' to quit.")

print(f"**Attempting to factor:** {to_factor}")

# Iterative factorization attempts with time measurements
for wheel_factorization_level in wheel_levels:
    for gear_factorization_level in gear_levels:
        print(f"--- Attempting with wheel_factorization_level={wheel_factorization_level}, gear_factorization_level={gear_factorization_level} ---")

        try:
            # Mark the start time
            start_time = time.time()
            factor = FindAFactor.find_a_factor(
                to_factor,
                use_congruence_of_squares=use_congruence_of_squares,
                use_gaussian_elimination=use_gaussian_elimination,
                node_count=node_count, node_id=node_id,
                gear_factorization_level=gear_factorization_level,
                wheel_factorization_level=wheel_factorization_level,
                smoothness_bound_multiplier=smoothness_bound_multiplier,
                batch_size_multiplier=batch_size_multiplier
            )
            # Mark the end time and calculate execution time
            end_time = time.time()
            execution_time = end_time - start_time

            if factor:
                print(f"**Factor Found!** (wheel:{wheel_factorization_level}, gear:{gear_factorization_level}): {factor}")
            else:
                print(f"No factor found (wheel:{wheel_factorization_level}, gear:{gear_factorization_level}).")
            print(f"**Execution Time:** {execution_time:.4f} seconds")  # Display execution time with emphasis
        except Exception as e:
            print(f"Error occurred (wheel:{wheel_factorization_level}, gear:{gear_factorization_level}): {str(e)}")
        print()  # Spacer for readability

# **Post-Run Options**
print("Factorization attempts completed for the input number.")
