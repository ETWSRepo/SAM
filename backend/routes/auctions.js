const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/connection');

const router = express.Router();

// GET all auctions
router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM auctions ORDER BY created_at DESC');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching auctions:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single auction
router.get('/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM auctions WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Auction not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching auction:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create auction
router.post('/', async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Auction name required' });
    }

    const id = uuidv4();
    await pool.query('INSERT INTO auctions (id, name, status) VALUES (?, ?, ?)', [id, name, 'active']);

    const [rows] = await pool.query('SELECT * FROM auctions WHERE id = ?', [id]);
    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Error creating auction:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update auction
router.put('/:id', async (req, res) => {
  try {
    const { name, status } = req.body;
    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(name);
    }
    if (status !== undefined) {
      updates.push('status = ?');
      values.push(status);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.id);
    await pool.query(`UPDATE auctions SET ${updates.join(', ')} WHERE id = ?`, values);

    const [rows] = await pool.query('SELECT * FROM auctions WHERE id = ?', [req.params.id]);
    res.json(rows[0]);
  } catch (error) {
    console.error('Error updating auction:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE auction
router.delete('/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM auctions WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting auction:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
