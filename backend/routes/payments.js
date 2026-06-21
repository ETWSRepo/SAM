const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/connection');

const router = express.Router();

// GET payments for auction
router.get('/:auctionId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT p.*, b.bidder_number, b.first_name, b.last_name
       FROM payments p
       LEFT JOIN bidders b ON p.bidder_id = b.id
       WHERE p.auction_id = ?
       ORDER BY b.bidder_number ASC`,
      [req.params.auctionId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching payments:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single payment
router.get('/:auctionId/:paymentId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM payments WHERE id = ? AND auction_id = ?',
      [req.params.paymentId, req.params.auctionId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching payment:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create payment (single or bulk)
router.post('/:auctionId', async (req, res) => {
  try {
    const isBulk = Array.isArray(req.body);
    const payments = isBulk ? req.body : [req.body];

    const created = [];
    for (const payment of payments) {
      const { bidder_id, method, amount, paid } = payment;

      if (!bidder_id) continue;

      const id = uuidv4();
      await pool.query(
        'INSERT INTO payments (id, auction_id, bidder_id, method, amount, paid) VALUES (?, ?, ?, ?, ?, ?)',
        [id, req.params.auctionId, bidder_id, method, amount, paid || false]
      );

      const [rows] = await pool.query('SELECT * FROM payments WHERE id = ?', [id]);
      created.push(rows[0]);
    }

    res.status(201).json(isBulk ? created : created[0]);
  } catch (error) {
    console.error('Error creating payment:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update payment
router.put('/:auctionId/:paymentId', async (req, res) => {
  try {
    const fields = ['method', 'amount', 'paid'];
    const updates = [];
    const values = [];

    fields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        values.push(req.body[field]);
      }
    });

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.paymentId);
    values.push(req.params.auctionId);
    await pool.query(`UPDATE payments SET ${updates.join(', ')} WHERE id = ? AND auction_id = ?`, values);

    const [rows] = await pool.query('SELECT * FROM payments WHERE id = ?', [req.params.paymentId]);
    res.json(rows[0]);
  } catch (error) {
    console.error('Error updating payment:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE payment
router.delete('/:auctionId/:paymentId', async (req, res) => {
  try {
    await pool.query('DELETE FROM payments WHERE id = ? AND auction_id = ?',
                     [req.params.paymentId, req.params.auctionId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting payment:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
