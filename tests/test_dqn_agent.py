import pytest

torch = pytest.importorskip("torch")

from dqn.agent import DQN, DQNAgent, ReplayBuffer


def test_dqn_output_shape():
    model = DQN(state_dim=108, action_dim=5)
    output = model(torch.randn(1, 108))
    assert output.shape == (1, 5)


def test_replay_buffer_sample():
    buffer = ReplayBuffer(capacity=10)
    for idx in range(5):
        buffer.push([0.0] * 108, idx, 1.0, [1.0] * 108, False)

    states, actions, rewards, next_states, dones = buffer.sample(3)

    assert states.shape == (3, 108)
    assert len(actions) == 3
    assert len(rewards) == 3
    assert next_states.shape == (3, 108)
    assert len(dones) == 3


def test_agent_select_action():
    agent = DQNAgent(state_dim=108, action_dim=5)
    action = agent.select_action([0.0] * 108)
    assert 0 <= action < 5


def test_epsilon_decays_during_replay_warmup():
    agent = DQNAgent(state_dim=108, action_dim=5, epsilon_decay=0.5)
    loss = agent.step([0.0] * 108, 0, 1.0, [1.0] * 108, False, batch_size=64)

    assert loss is None
    assert agent.epsilon == 0.5
