idf_component_register(
    SRCS
        "mldsa_native.c"
        "src/sign.c"
        "src/packing.c"
        "src/poly.c"
        "src/poly_kl.c"
        "src/polyvec.c"
        "src/polyvec_lazy.c"
        "src/ct.c"
        "src/debug.c"
        "src/fips202/fips202.c"
        "src/fips202/fips202x4.c"
        "src/fips202/keccakf1600.c"
    INCLUDE_DIRS
        "."
        "src"
        "src/fips202"
)

target_compile_definitions(__idf_mldsa PRIVATE MLD_CONFIG_PARAMETER_SET=87)
