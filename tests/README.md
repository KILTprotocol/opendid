## Test Suite for OpenDID

This test includes end-to-end testing for the OpenDID service.


### Notes
1. The tests are hardcoded for email credentials (for example issed by socialKYC)
2. Hardcorded values are stored in `test_config.ts` file.
3. `SEED` environment variable must be set for the DID of the test user. You can use a `.env` file to set it.

### Run the tests
Use the following commands to run the tests.
```bash
yarn
```

```bash
yarn test
```
