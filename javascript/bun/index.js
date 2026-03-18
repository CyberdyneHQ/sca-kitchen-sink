import { Server } from 'socket.io';
import axios from 'axios';

const io = new Server(3000);

// Function to make a GET request to a public API using axios
function fetchDataAndEmit(socket) {
    axios.get('https://jsonplaceholder.typicode.com/todos/1')
        .then((response) => {
            console.log('API response:', response.data);

            // Send the API response back to the client
            socket.emit('apiResponse', response.data);
        })
        .catch((error) => {
            console.error('Error fetching data from API:', error);
        });
}

// Set up a basic socket.io server
io.on('connection', (socket) => {
    console.log('a user connected');

    // Listen for a 'message' event from the client
    socket.on('message', (msg) => {
        console.log('message received:', msg);
        fetchDataAndEmit(socket);
    });

    // Handle client disconnect
    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

console.log('Socket.io server running on port 3000');
