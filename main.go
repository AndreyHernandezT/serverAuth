package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

var jwtSecret = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDDo9KAQ+DUi2Xqi5SqkqSkhP3/T0rofHL4LdRn8lAb6nJ5gy2L
Ca64KyYky1VrR4CZH286cQDHUiuqSmtRAxyds0I+qtqMDiiclv3imW9TMVOCxVCP
JVJv0DyGgGHwbOgvA2vdR5i/TSqRDqua0qAl/dBXJyqgV9pMjzQGDfgKswIDAQAB
AoGAWTZSHjVVx/ZNIjhGMcYvF+qhXJQO55cgYjWb306q4x/01Z5Q3U8sAkWC3lJu
gD4Z0Tl5Yh/3p+y7hqrq5wVRPXcniwGrepEdgyObJ54U4SW7k4XHaRKUlYGmG5jl
960TYPGNAPjDSTfy8X4lktMRMQPu6u53W07Aoq3POD+Jr5kCQQD45tthShRlF40l
KfW+S4Hhhe62HkQszNfZnRiIFoPzhCuGUUgqlWw7DQXoOHw84YO/ZlMI6uWez6nq
WmaOOMBVAkEAyTgemhudQJNo2Udpk9KBbUx5tO9vZx0yawGNjaZHuZXIbPCe8wT4
J+6bELvfSLV+MkAwSmWCFRXladavMb6G5wJBAN6PRvEKlYwDcCEgEO4UhFGNOfM8
wwcwL34Ve78MKvbPYz/aZGY3cCypK3QHNggWOoEl1O+vYp0L4Up9hSB83HUCQCi3
J1INlmMzsLqOfamApdnE6LeY31ThDouic88ev1KpITYR9ke8UK5b1JqtOUAQIWnv
nRXgtlKn7JTe8PJC2C8CQQC0cHFdQEGeYpbNbJG57oQgLK1afdBOYuc5E8wgsl9x
+d7ZCcc93ltHw+Owv6Qh6IMYt8yaoPtVHZpmkzqQcugI
-----END RSA PRIVATE KEY-----`) // Clave secreta para JWT

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	privateBytes, err := ioutil.ReadFile("private.rsa")
	if err != nil {
		log.Fatal("Cannot read private key file")
	}
	publicBytes, err := ioutil.ReadFile("public.rsa.pub")
	if err != nil {
		log.Fatal("Cannot read public key file")
	}
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytes)
	if err != nil {
		log.Fatal("Cannot parce private key")
	}
	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytes)
	if err != nil {
		log.Fatal("Cannot parce private key")
	}
}

func main() {
	router := mux.NewRouter()

	// Endpoint para registrar un nuevo usuario
	router.HandleFunc("/register", crearUsuario).Methods("POST")

	// Endpoint para iniciar sesión
	router.HandleFunc("/login", iniciarSesion).Methods("POST")

	// Endopoint para validar token
	router.HandleFunc("/validate", validateToken).Methods("GET")

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

	// Conecta a la base de datos
	client, err := conectarMongoDB()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	collection := client.Database(mongoDBConfig().DBName).Collection(mongoDBConfig().CollectionName)
	filter := bson.M{"email": usuario.Email}

	var existingUser Usuario
	err = collection.FindOne(context.Background(), filter).Decode(&existingUser)

	if err == nil {
		// El correo electrónico ya existe en la base de datos
		respondWithError(w, http.StatusConflict, "El correo electrónico ya está registrado")
		return
	} else if err != mongo.ErrNoDocuments {
		// Ocurrió un error al buscar en la base de datos
		respondWithError(w, http.StatusConflict, "Error, intentelo más tarde")
		return
	}

	// Encripta la contraseña antes de guardarla en la base de datos
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(usuario.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	usuario.Password = string(hashedPassword)

	// Inserta el usuario en la colección

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
		respondWithError(w, http.StatusInternalServerError, "Error al generar el token JWT "+err.Error())
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

// Función para validar un token JWT
func validateToken_(tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return false, err
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, nil
	} else {
		return false, nil
	}
}

func validateToken(w http.ResponseWriter, r *http.Request) {

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		respondWithError(w, http.StatusUnauthorized, "Token de autenticación requerido")
		return
	}
	valid, err := validateToken_(tokenString)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Error al validar el token")
		return
	}

	if !valid {
		respondWithError(w, http.StatusUnauthorized, "Token invalido")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Bienvenido al sistema"})

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
