# SAM Backend - Phase 1 Deployment Guide

## Overview
This is the Phase 1 backend for Silent Auction Manager (SAM) — a Node.js + Express API backed by MySQL. It provides REST endpoints for managing auctions, items, bidders, winners, payments, and settings.

## Prerequisites
- Node.js 14+ installed on your Hostinger server
- MySQL database already set up: `u177039107_sam`
- MySQL credentials ready

## Step 1: Set Up MySQL Schema

1. Connect to your Hostinger MySQL database (via cPanel or phpMyAdmin)
2. Select the database: `u177039107_sam`
3. Open the SQL editor and run the contents of `schema.sql`
   - This creates all 6 tables: auctions, items, bidders, winners, payments, settings

## Step 2: Create .env File

1. In the `backend/` directory, create a file named `.env` (copy from `.env.example`)
2. Fill in your Hostinger MySQL credentials:
   ```
   PORT=3000
   NODE_ENV=production
   DB_HOST=localhost
   DB_USER=u177039107_sam
   DB_PASS=uemk$td*TjnAD9t4HXeYdsBQfqDDSZ4m
   DB_NAME=u177039107_sam
   DB_PORT=3306
   API_KEY=your-secret-api-key-here-change-this
   CORS_ORIGIN=https://etccapps.com
   ```
3. **Replace `API_KEY`** with a strong, unique key — this protects your API

## Step 3: Install Dependencies

On your Hostinger server, run:
```bash
cd backend
npm install
```

This installs: express, mysql2, dotenv, uuid, cors

## Step 4: Deploy to Hostinger

**Option A: Git (Recommended)**
```bash
cd ~/public_html/apps/sam
git add backend/
git commit -m "Add Phase 1 backend"
git push origin main
```

**Option B: FTP**
- Upload all files in `backend/` to `/public_html/apps/sam/backend/`
- Keep directory structure: `backend/db/`, `backend/routes/`, `backend/middleware/`, etc.

## Step 5: Start the Server

On Hostinger, your Node.js app will auto-start via cPanel application management or npm/node processes.

**To test locally:**
```bash
npm start
```

Server will run on `http://localhost:3000` (or port specified in .env)

## Step 6: Test the API

Use curl or Postman to test:

```bash
# Health check
curl "http://localhost:3000/health?apiKey=your-secret-api-key"

# Create auction
curl -X POST "http://localhost:3000/api/auctions?apiKey=your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{"name":"2025 Car Show Silent Auction"}'

# Get auctions
curl "http://localhost:3000/api/auctions?apiKey=your-secret-api-key"
```

## API Endpoints

All endpoints require `?apiKey=YOUR_API_KEY` query param or `X-API-Key` header.

### Auctions
- `GET    /api/auctions` — list all
- `GET    /api/auctions/:id` — get one
- `POST   /api/auctions` — create (body: `{name}`)
- `PUT    /api/auctions/:id` — update (body: `{name, status}`)
- `DELETE /api/auctions/:id` — delete

### Items
- `GET    /api/items/:auctionId` — list items in auction
- `GET    /api/items/:auctionId/:itemId` — get one item
- `POST   /api/items/:auctionId` — create item
- `PUT    /api/items/:auctionId/:itemId` — update item
- `DELETE /api/items/:auctionId/:itemId` — delete item

### Bidders
- `GET    /api/bidders/:auctionId` — list bidders
- `GET    /api/bidders/:auctionId/:bidderId` — get one
- `POST   /api/bidders/:auctionId` — create bidder
- `PUT    /api/bidders/:auctionId/:bidderId` — update bidder
- `DELETE /api/bidders/:auctionId/:bidderId` — delete bidder

### Winners
- `GET    /api/winners/:auctionId` — list winners
- `GET    /api/winners/:auctionId/:winnerId` — get one
- `POST   /api/winners/:auctionId` — create winner
- `PUT    /api/winners/:auctionId/:winnerId` — update winner
- `DELETE /api/winners/:auctionId/:winnerId` — delete winner

### Payments
- `GET    /api/payments/:auctionId` — list payments
- `GET    /api/payments/:auctionId/:paymentId` — get one
- `POST   /api/payments/:auctionId` — create payment
- `PUT    /api/payments/:auctionId/:paymentId` — update payment
- `DELETE /api/payments/:auctionId/:paymentId` — delete payment

### Settings
- `GET    /api/settings/:auctionId` — get all settings for auction
- `GET    /api/settings/:auctionId/:key` — get single setting
- `POST   /api/settings/:auctionId` — upsert multiple settings
- `DELETE /api/settings/:auctionId/:key` — delete setting

## Example Requests

### Create an Auction
```bash
curl -X POST "http://localhost:3000/api/auctions?apiKey=your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "2025 Car Show Silent Auction"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "2025 Car Show Silent Auction",
  "status": "active",
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

### Add Item to Auction
```bash
curl -X POST "http://localhost:3000/api/items/550e8400-e29b-41d4-a716-446655440000?apiKey=your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "item_number": "200-1",
    "description": "1963 Corvette Stingray",
    "item_value": "$5,000.00",
    "category_code": "200",
    "category_name": "Corvette Items",
    "donor_name": "John Smith",
    "donor_email": "john@example.com",
    "reserve_amount": "$2,500.00"
  }'
```

## Troubleshooting

**"Cannot find module 'mysql2'"**
- Run `npm install` in the backend directory

**"API key required" error**
- Check that you're passing `?apiKey=...` or `X-API-Key` header

**"Database connection failed"**
- Verify .env credentials match Hostinger MySQL settings
- Check that database `u177039107_sam` exists

**CORS errors when calling from frontend**
- Ensure `CORS_ORIGIN` in .env matches your frontend domain

## Next Steps

Once Phase 1 is deployed and tested:

**Phase 2:** Refactor the frontend (index.html) to use these API endpoints instead of localStorage. This will:
- Remove all localStorage calls
- Add API request functions
- Update data loading/saving logic
- Implement authentication between frontend and backend

See the project README for Phase 2 details.
