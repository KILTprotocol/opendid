import 'dotenv/config'
import { authentication } from './authentication'
import { TestState } from './test_state'
import { authorize } from './authorize'
import { challenge } from './challenge'

describe('OpenDID', () => {
  it('should support Authorization Code Flow', async () => {
    const testState = new TestState()

    await authorize(testState)
    await challenge(testState)
    await authentication(testState)
  })
})
