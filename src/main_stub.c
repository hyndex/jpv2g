/*
 * Stub entry point so `platformio run` can link successfully when building the
 * library as an application. Skipped during unit-test builds.
 */
#if !defined(UNIT_TEST) && !defined(PIO_UNIT_TESTING)
int main(void) {
    return 0;
}
#endif
