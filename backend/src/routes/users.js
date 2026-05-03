const express = require('express');

const { listAssignableUsers } = require('../services/users');

const router = express.Router();

router.get('/assignees', async (_req, res) => {
  try {
    const users = await listAssignableUsers();
    return res.json({ users });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;