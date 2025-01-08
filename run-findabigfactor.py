from FindAFactor import find_a_factor

to_factor = 1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139

factor = find_a_factor(
    to_factor,
    use_congruence_of_squares=False,
    node_count=1, node_id=0,
    gear_factorization_level=11,
    wheel_factorization_level=7,
    smoothness_bound_multiplier=1.0,
    batch_size_multiplier=512.0
)
