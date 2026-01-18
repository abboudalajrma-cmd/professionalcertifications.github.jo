# ExamVault

## Overview

ExamVault is a web application for managing and analyzing student exam results. It allows users to upload exam data from Excel files, view results in a dashboard, and filter/search through student performance data. The application features a modern React frontend with a Node.js/Express backend, using PostgreSQL for data persistence.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: TanStack React Query for server state management and caching
- **Styling**: Tailwind CSS with custom CSS variables for theming (light/dark mode support)
- **UI Components**: shadcn/ui component library built on Radix UI primitives
- **Animations**: Framer Motion for smooth page transitions and interactions
- **File Parsing**: XLSX library for client-side Excel file parsing

### Backend Architecture
- **Runtime**: Node.js with Express 5
- **Language**: TypeScript with ES modules
- **API Design**: RESTful endpoints defined in `shared/routes.ts` with Zod schemas for validation
- **Development Server**: Vite dev server with HMR proxied through Express

### Data Storage
- **Database**: PostgreSQL with connection pooling via `pg`
- **ORM**: Drizzle ORM for type-safe database queries
- **Schema**: Defined in `shared/schema.ts` using Drizzle's PostgreSQL schema builder
- **Migrations**: Drizzle Kit for schema migrations (output to `./migrations`)

### Shared Code
- **Location**: `shared/` directory contains code used by both frontend and backend
- **Schema**: Database types and Zod validation schemas
- **Routes**: API endpoint definitions with input/output schemas for type safety

### Build System
- **Frontend**: Vite bundles the React app to `dist/public`
- **Backend**: esbuild bundles the server to `dist/index.cjs` with strategic dependency bundling for faster cold starts
- **Development**: `tsx` runs TypeScript directly without compilation

### Key Design Patterns
- **Type Sharing**: Drizzle-zod generates Zod schemas from database tables, ensuring type consistency across the stack
- **API Contract**: Routes are defined with Zod schemas in `shared/routes.ts`, providing runtime validation and TypeScript types
- **Storage Interface**: `IStorage` interface in `server/storage.ts` abstracts database operations, enabling potential future storage backends

## External Dependencies

### Database
- **PostgreSQL**: Primary data store (connection via `DATABASE_URL` environment variable)
- **connect-pg-simple**: Session storage in PostgreSQL (available but may not be currently used)

### Third-Party Libraries
- **@tanstack/react-query**: Async state management and caching
- **drizzle-orm** + **drizzle-zod**: Type-safe ORM and schema validation
- **xlsx**: Excel file parsing (client-side)
- **framer-motion**: Animation library
- **Radix UI**: Accessible UI component primitives (accordion, dialog, dropdown, tabs, etc.)
- **class-variance-authority** + **clsx** + **tailwind-merge**: CSS class utilities

### Development Tools
- **Vite**: Frontend bundler with HMR
- **esbuild**: Backend bundler for production
- **tsx**: TypeScript execution for development
- **drizzle-kit**: Database migration tooling