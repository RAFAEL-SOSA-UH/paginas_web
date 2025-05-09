const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt'); // Importar bcrypt para el manejo de contraseñas
const jwt = require('jsonwebtoken'); // Opcional: Para generar un token JWT para autenticación

// Crear una instancia de la app de Express
const app = express();

// Usar CORS para permitir solicitudes de otros dominios
app.use(cors());

// Para manejar datos en formato JSON en el cuerpo de las solicitudes
app.use(express.json());

// Conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Sin contraseña por defecto en XAMPP
  database: 'usuarios', // El nombre de tu base de datos
});

// Verificar si la conexión es exitosa
db.connect((err) => {
  if (err) {
    console.error('Error de conexión:', err);
  } else {
    console.log('Conectado a MySQL');
  }
});

// Ruta para insertar un usuario en la base de datos
app.post('/api/usuarios', (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  // Encriptar la contraseña antes de guardarla
  bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
    if (err) {
      console.error('Error al encriptar contraseña:', err);
      return res.status(500).json({ error: 'Error al encriptar la contraseña' });
    }

    // Query para insertar datos
    const query = 'INSERT INTO users (nombre, correo, contrasena) VALUES (?, ?, ?)';
    
    db.query(query, [nombre, correo, hashedPassword], (err, result) => {
      if (err) {
        console.error('Error al insertar:', err);
        return res.status(500).json({ error: 'Error al guardar usuario' });
      }
      res.json({ mensaje: 'Usuario guardado correctamente', id: result.insertId });
    });
  });
});

// Ruta de login para verificar el usuario y la contraseña
app.post('/api/login', (req, res) => {
  const { uname, password } = req.body;

  // Query para obtener el usuario por nombre
  db.query('SELECT * FROM users WHERE nombre = ?', [uname], (err, results) => {
    if (err) {
      console.error('Error al verificar usuario:', err);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }

    if (results.length === 0) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const user = results[0];

    // Comparar la contraseña proporcionada con la almacenada (encriptada)
    bcrypt.compare(password, user.contrasena, (err, isMatch) => {
      if (err) {
        console.error('Error al comparar contraseñas:', err);
        return res.status(500).json({ error: 'Error al verificar la contraseña' });
      }

      if (!isMatch) {
        return res.status(400).json({ error: 'Contraseña incorrecta' });
      }

      // Opcional: Crear un token JWT para la sesión
      const token = jwt.sign({ id: user.id, nombre: user.nombre }, 'tu_secreto', { expiresIn: '1h' });

      // Devolver el token y un mensaje de éxito
      res.json({ message: 'Login exitoso', token });
    });
  });
});

// Configurar el puerto y levantar el servidor
app.listen(3000, () => {
  console.log('Servidor backend escuchando en http://localhost:3000');
});
