/query-based-project  
│── /src  
│   │── /config              # Database & environment configurations  
│   │   │── db.js            # MySQL connection setup  
│   │── /queries             # Raw SQL queries for different modules  
│   │   │── userQueries.js  
│   │   │── adminQueries.js  
│   │── /controllers         # Business logic for API endpoints  
│   │   │── /user            # User-related controllers  
│   │   │   │── userController.js  
│   │   │── /admin           # Admin-related controllers  
│   │   │   │── adminController.js  
│   │── /routes              # API routes  
│   │   │── /user            # Routes for users  
│   │   │   │── userRoutes.js  
│   │   │── /admin           # Routes for admins  
│   │   │   │── adminRoutes.js  
│   │── /middlewares         # Middleware functions (authentication, role validation)  
│   │   │── authMiddleware.js  
│   │   │── roleMiddleware.js  
│   │── /services            # Business logic layer for better separation  
│   │   │── userService.js  
│   │   │── adminService.js  
│   │── /utils               # Utility functions (error handling, response formatting)  
│   │   │── responseHandler.js  
│   │── /validators          # Request validation using Joi  
│   │   │── userValidator.js  
│   │── app.js               # Main Express app setup  
│── /tests                   # Unit & integration tests  
│── package.json             # Dependencies & scripts  
│── .env                     # Environment variables  
│── README.md                # Project Documentation  
