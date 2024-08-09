const dotenv = require('dotenv');
dotenv.config({ path: './config.env' }); 

const app = require('./app');
const mongoose = require('mongoose');

mongoose.connect(process.env.CONN_STR)
    .then(() => {
        console.log('DB CONNECTION SUCCESSFUL');
        const port = process.env.PORT || 3000;
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    })
    .catch(error => {
        console.log('Error connecting to MongoDB:', error);
    });

    
