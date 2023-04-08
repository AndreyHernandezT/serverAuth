package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("my-secret-key") // Clave secreta para JWT

func main() {
	router := mux.NewRouter()

	// Endpoint para registrar un nuevo usuario
	router.HandleFunc("/register", crearUsuario).Methods("POST")

	// Endpoint para iniciar sesión
	router.HandleFunc("/login", iniciarSesion).Methods("POST")

	// Endpoint para olvidar contraseña
	//router.HandleFunc("/forgot", ForgotPassword).Methods("POST")

	// Endpoint para reiniciar contraseña
	//router.HandleFunc("/reset/{token}", ResetPassword).Methods("POST")

	log.Fatal(http.ListenAndServe(":8000", router))
}

// Usuario representa la estructura de datos para un usuario
type Usuario struct {
	ID       string `json:"id,omitempty"`
	Nombre   string `json:"nombre,omitempty"`
	Apellido string `json:"apellido,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// Token representa la estructura de datos para un token JWT
type Token struct {
	Token string `json:"token,omitempty"`
}

// MongoDBConfig representa la configuración para la conexión a la base de datos MongoDB
type MongoDBConfig struct {
	URI            string
	DBName         string
	CollectionName string
}

func mongoDBConfig() MongoDBConfig {
	return MongoDBConfig{
		URI:            "mongodb://localhost:27017", // Cambiar por la URL de tu base de datos MongoDB
		DBName:         "multiple_pdf_database",     // Cambiar por el nombre de tu base de datos
		CollectionName: "users",                     // Cambiar por el nombre de tu colección
	}
}
func conectarMongoDB() (*mongo.Client, error) {
	// Obtener la configuración de MongoDB
	config := mongoDBConfig()

	// Establecer las opciones de conexión a MongoDB
	clientOptions := options.Client().ApplyURI(config.URI)

	// Establecer la conexión a MongoDB
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Error al establecer la conexión a MongoDB: %v", err)
		return nil, err
	}

	// Comprobar si la conexión es válida
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("Error al verificar la conexión a MongoDB: %v", err)
		return nil, err
	}

	fmt.Println("Conexión exitosa a MongoDB")

	return client, nil
}

// Crea un nuevo usuario en la base de datos
func crearUsuario(w http.ResponseWriter, r *http.Request) {
	var usuario Usuario
	err := decodeJSONBody(w, r, &usuario)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	// Encripta la contraseña antes de guardarla en la base de datos
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(usuario.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	usuario.Password = string(hashedPassword)

	// Conecta a la base de datos
	client, err := conectarMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Inserta el usuario en la colección
	collection := client.Database(mongoDBConfig().DBName).Collection(mongoDBConfig().CollectionName)
	result, err := collection.InsertOne(context.Background(), usuario)
	if err != nil {
		log.Fatal(err)
	}

	// Retorna el ID del usuario creado
	respondWithJSON(w, http.StatusOK, bson.M{"id": result.InsertedID})
}

// Inicia sesión de un usuario y genera un token JWT
func iniciarSesion(w http.ResponseWriter, r *http.Request) {
	var usuario Usuario
	err := decodeJSONBody(w, r, &usuario)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return
	}

	// Conecta a la base de datos
	client, err := conectarMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Busca el usuario por email
	collection := client.Database(mongoDBConfig().DBName).Collection(mongoDBConfig().CollectionName)
	filter := bson.M{"email": usuario.Email}
	var resultado Usuario
	err = collection.FindOne(context.Background(), filter).Decode(&resultado)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Compara la contraseña ingresada con la almacenada en la base de datos
	err = bcrypt.CompareHashAndPassword([]byte(resultado.Password), []byte(usuario.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Email o contraseña incorrectos")
		return
	}

	// Genera un nuevo token JWT
	token, err := generarTokenJWT(resultado.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error al generar el token JWT")
		return
	}

	// Retorna el token JWT
	respondWithJSON(w, http.StatusOK, Token{Token: token})
}

// Genera un token JWT para el ID de usuario dado
func generarTokenJWT(userID string) (string, error) {
	// Crea el token con el algoritmo HS256 y la clave secreta
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 1).Unix(), // Expira en 1 hora
	})

	// Firma el token con la clave secreta
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Decodifica el cuerpo de una solicitud HTTP en formato JSON y lo asigna a una estructura dada
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	defer r.Body.Close()

	// Limita el tamaño máximo del cuerpo de la solicitud a 1 MB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	// Decodifica el cuerpo de la solicitud en formato JSON
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(v)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Datos inválidos")
		return err
	}

	return nil
}

// Responde con un error en formato JSON
func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	respondWithJSON(w, statusCode, map[string]string{"error": message})
}

// Responde con datos en formato JSON
func respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Println("Error al responder con JSON:", err)
	}
}
