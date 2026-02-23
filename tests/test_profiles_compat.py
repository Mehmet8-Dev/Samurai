import importlib
import warnings
import unittest


class TestProfilesCompat(unittest.TestCase):
    def test_profiles_module_emits_deprecation_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            mod = importlib.import_module("ddos_samurai.profiles")
            importlib.reload(mod)

        self.assertTrue(any(isinstance(w.message, DeprecationWarning) for w in caught))

    def test_profiles_alias_exports_workload_symbols(self):
        from ddos_samurai import profiles
        from ddos_samurai import workload_profiles

        self.assertIs(profiles.TEST_PROFILES, workload_profiles.TEST_PROFILES)
        self.assertIs(profiles.print_profiles, workload_profiles.print_profiles)
