package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Константы для ролей
const (
	RoleClient   = "Заказчик" // From CSV: Заказчик
	RoleManager  = "Менеджер" // From CSV: Менеджер
	RoleMaster   = "Мастер"   // From CSV: Мастер
	RoleOperator = "Оператор" // From CSV: Оператор
)

// Ключ для хранения пользователя в контексте
type contextKey string

const userContextKey contextKey = "user"

// Секретный ключ для JWT
var jwtSecret = []byte("my-secret-key-change-me-in-production")

// Структура для JWT Claims
type Claims struct {
	UserID int    `json:"user_id"`
	Type   string `json:"type"`
	jwt.RegisteredClaims
}

// ============ МОДЕЛИ ============

type User struct {
	UserID   int    `json:"user_id"`
	FIO      string `json:"fio"`
	Phone    string `json:"phone"`
	Login    string `json:"login"`
	Password string `json:"password,omitempty"` // omitempty - не выводить в JSON
	Type     string `json:"type"`
}

type Comment struct {
	CommentID int    `json:"comment_id"`
	Message   string `json:"message"`
	MasterID  int    `json:"master_id"`
	RequestID int    `json:"request_id"`
	MasterFIO string `json:"master_fio,omitempty"` // Для отображения на фронте
}

type Request struct {
	RequestID          int        `json:"request_id"`
	StartDate          time.Time  `json:"start_date"`
	HomeTechType       string     `json:"home_tech_type"`
	HomeTechModel      string     `json:"home_tech_model"`
	ProblemDescription string     `json:"problem_description"`
	RequestStatus      string     `json:"request_status"`
	CompletionDate     *time.Time `json:"completion_date"`
	RepairParts        *string    `json:"repair_parts"`
	MasterID           *int       `json:"master_id"`
	ClientID           int        `json:"client_id"`
	// Дополнительные поля из JOIN
	ClientName  string    `json:"client_name,omitempty"`
	ClientPhone string    `json:"client_phone,omitempty"`
	MasterName  *string   `json:"master_name,omitempty"`
	MasterPhone *string   `json:"master_phone,omitempty"`
	Comments    []Comment `json:"comments,omitempty"` // Список комментариев
}

type LoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CreateRequestInput struct {
	HomeTechType       string `json:"home_tech_type" binding:"required"`
	HomeTechModel      string `json:"home_tech_model" binding:"required"`
	ProblemDescription string `json:"problem_description" binding:"required"`
	ClientID           int    `json:"client_id"` // Устанавливается автоматически из текущего пользователя
}

type UpdateRequestInput struct {
	HomeTechType       *string `json:"home_tech_type"`
	HomeTechModel      *string `json:"home_tech_model"`
	ProblemDescription *string `json:"problem_description"`
	RequestStatus      *string `json:"request_status"`
	RepairParts        *string `json:"repair_parts"`
}

type AssignMasterInput struct {
	MasterID int `json:"master_id" binding:"required"`
}

type CreateCommentInput struct {
	Message string `json:"message" binding:"required"`
}

// ============ СЛОЙ БД ============

// Авторизация пользователя
func AuthenticateUser(ctx context.Context, pool *pgxpool.Pool, login, password string) (*User, error) {
	query := `
		SELECT user_id, fio, phone, login, type 
		FROM users 
		WHERE login = $1 AND password = $2
	`

	var user User
	err := pool.QueryRow(ctx, query, login, password).Scan(
		&user.UserID,
		&user.FIO,
		&user.Phone,
		&user.Login,
		&user.Type,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("неверный логин или пароль")
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Генерация JWT токена
func GenerateToken(user User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.UserID,
		Type:   user.Type,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Получить комментарии для заявки
func GetCommentsForRequest(ctx context.Context, pool *pgxpool.Pool, requestID int) ([]Comment, error) {
	query := `
		SELECT c.comment_id, c.message, c.master_id, c.request_id, u.fio
		FROM comments c
		JOIN users u ON c.master_id = u.user_id
		WHERE c.request_id = $1
		ORDER BY c.comment_id
	`
	rows, err := pool.Query(ctx, query, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var c Comment
		err := rows.Scan(&c.CommentID, &c.Message, &c.MasterID, &c.RequestID, &c.MasterFIO)
		if err != nil {
			return nil, err
		}
		comments = append(comments, c)
	}
	return comments, nil
}

// Получить все заявки с полной информацией (с учетом роли пользователя)
func GetAllRequests(ctx context.Context, pool *pgxpool.Pool, user *User) ([]Request, error) {
	var query string
	var args []interface{}

	// Базовый SELECT
	selectPart := `
		SELECT 
			r.request_id,
			r.start_date,
			r.home_tech_type,
			r.home_tech_model,
			r.problem_description,
			r.request_status,
			r.completion_date,
			r.repair_parts,
			r.master_id,
			r.client_id,
			c.fio as client_name,
			c.phone as client_phone,
			m.fio as master_name,
			m.phone as master_phone
		FROM requests r
		JOIN users c ON r.client_id = c.user_id
		LEFT JOIN users m ON r.master_id = m.user_id
	`

	if user.Type == RoleClient {
		query = selectPart + ` WHERE r.client_id = $1 ORDER BY r.start_date DESC`
		args = []interface{}{user.UserID}
	} else if user.Type == RoleMaster {
		query = selectPart + ` WHERE r.master_id = $1 ORDER BY r.start_date DESC`
		args = []interface{}{user.UserID}
	} else {
		// Менеджер и Оператор видят все
		query = selectPart + ` ORDER BY r.start_date DESC`
		args = []interface{}{}
	}

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []Request
	for rows.Next() {
		var r Request
		err := rows.Scan(
			&r.RequestID,
			&r.StartDate,
			&r.HomeTechType,
			&r.HomeTechModel,
			&r.ProblemDescription,
			&r.RequestStatus,
			&r.CompletionDate,
			&r.RepairParts,
			&r.MasterID,
			&r.ClientID,
			&r.ClientName,
			&r.ClientPhone,
			&r.MasterName,
			&r.MasterPhone,
		)
		if err != nil {
			return nil, err
		}
		// Комментарии загружаем отдельно при просмотре конкретной заявки, чтобы не грузить список
		requests = append(requests, r)
	}

	return requests, nil
}

// Получить заявку по ID (с учетом роли пользователя)
func GetRequestByID(ctx context.Context, pool *pgxpool.Pool, id int, user *User) (*Request, error) {
	// То же самое, что и список, только с фильтром по ID
	selectPart := `
		SELECT 
			r.request_id,
			r.start_date,
			r.home_tech_type,
			r.home_tech_model,
			r.problem_description,
			r.request_status,
			r.completion_date,
			r.repair_parts,
			r.master_id,
			r.client_id,
			c.fio as client_name,
			c.phone as client_phone,
			m.fio as master_name,
			m.phone as master_phone
		FROM requests r
		JOIN users c ON r.client_id = c.user_id
		LEFT JOIN users m ON r.master_id = m.user_id
		WHERE r.request_id = $1
	`
	var args []interface{}
	args = append(args, id)

	if user.Type == RoleClient {
		selectPart += ` AND r.client_id = $2`
		args = append(args, user.UserID)
	} else if user.Type == RoleMaster {
		selectPart += ` AND r.master_id = $2`
		args = append(args, user.UserID)
	}

	var r Request
	err := pool.QueryRow(ctx, selectPart, args...).Scan(
		&r.RequestID,
		&r.StartDate,
		&r.HomeTechType,
		&r.HomeTechModel,
		&r.ProblemDescription,
		&r.RequestStatus,
		&r.CompletionDate,
		&r.RepairParts,
		&r.MasterID,
		&r.ClientID,
		&r.ClientName,
		&r.ClientPhone,
		&r.MasterName,
		&r.MasterPhone,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Загружаем комментарии
	comments, err := GetCommentsForRequest(ctx, pool, r.RequestID)
	if err != nil {
		// Не падаем, если комменты не загрузились, но логируем
		log.Printf("Ошибка загрузки комментариев: %v", err)
	} else {
		r.Comments = comments
	}

	return &r, nil
}

// Создать новую заявку
func CreateRequest(ctx context.Context, pool *pgxpool.Pool, input CreateRequestInput) (int, error) {
	query := `
		INSERT INTO requests (
			start_date, 
			home_tech_type, 
			home_tech_model, 
			problem_description, 
			request_status,
			client_id
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING request_id
	`

	var requestID int
	err := pool.QueryRow(ctx, query,
		time.Now(),
		input.HomeTechType,
		input.HomeTechModel,
		input.ProblemDescription,
		"Новая заявка",
		input.ClientID,
	).Scan(&requestID)

	return requestID, err
}

// Обновить заявку (с проверкой прав доступа)
func UpdateRequest(ctx context.Context, pool *pgxpool.Pool, id int, input UpdateRequestInput, user *User) error {
	// Сначала проверяем права доступа
	var clientID int
	var masterID *int
	err := pool.QueryRow(ctx,
		"SELECT client_id, master_id FROM requests WHERE request_id = $1",
		id,
	).Scan(&clientID, &masterID)

	if err == pgx.ErrNoRows {
		return fmt.Errorf("заявка с ID %d не найдена", id)
	}
	if err != nil {
		return err
	}

	// Проверка прав доступа
	if user.Type == RoleClient {
		if clientID != user.UserID {
			return fmt.Errorf("нет доступа к редактированию этой заявки")
		}
		if input.RequestStatus != nil {
			return fmt.Errorf("клиент не может изменять статус заявки")
		}
	} else if user.Type == RoleMaster {
		if masterID == nil || *masterID != user.UserID {
			return fmt.Errorf("нет доступа к редактированию этой заявки")
		}
	}

	// Динамически строим UPDATE запрос
	query := "UPDATE requests SET "
	params := []interface{}{}
	paramIndex := 1

	if input.HomeTechType != nil {
		query += fmt.Sprintf("home_tech_type = $%d, ", paramIndex)
		params = append(params, *input.HomeTechType)
		paramIndex++
	}
	if input.HomeTechModel != nil {
		query += fmt.Sprintf("home_tech_model = $%d, ", paramIndex)
		params = append(params, *input.HomeTechModel)
		paramIndex++
	}
	if input.ProblemDescription != nil {
		query += fmt.Sprintf("problem_description = $%d, ", paramIndex)
		params = append(params, *input.ProblemDescription)
		paramIndex++
	}
	if input.RequestStatus != nil {
		query += fmt.Sprintf("request_status = $%d, ", paramIndex)
		params = append(params, *input.RequestStatus)
		paramIndex++
	}
	if input.RepairParts != nil {
		query += fmt.Sprintf("repair_parts = $%d, ", paramIndex)
		params = append(params, *input.RepairParts)
		paramIndex++
	}

	// Убираем последнюю запятую
	if len(params) > 0 {
		query = query[:len(query)-2]
	} else {
		// Ничего не обновляем
		return nil
	}

	// Добавляем WHERE
	query += fmt.Sprintf(" WHERE request_id = $%d", paramIndex)
	params = append(params, id)

	result, err := pool.Exec(ctx, query, params...)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("заявка с ID %d не найдена", id)
	}

	return nil
}

// Назначить мастера на заявку
func AssignMasterToRequest(ctx context.Context, pool *pgxpool.Pool, requestID, masterID int) error {
	// Проверяем что пользователь является мастером
	var userType string
	err := pool.QueryRow(ctx,
		"SELECT type FROM users WHERE user_id = $1",
		masterID,
	).Scan(&userType)

	if err == pgx.ErrNoRows {
		return fmt.Errorf("пользователь с ID %d не найден", masterID)
	}
	if err != nil {
		return err
	}
	if userType != RoleMaster {
		return fmt.Errorf("пользователь с ID %d не является мастером", masterID)
	}

	// Назначаем мастера
	query := `
		UPDATE requests 
		SET master_id = $1,
		    request_status = CASE 
		        WHEN request_status = 'Новая заявка' THEN 'В процессе ремонта'
		        ELSE request_status
		    END
		WHERE request_id = $2
	`

	result, err := pool.Exec(ctx, query, masterID, requestID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("заявка с ID %d не найдена", requestID)
	}

	return nil
}

// Добавить комментарий
func AddComment(ctx context.Context, pool *pgxpool.Pool, requestID int, masterID int, message string) error {
	// Проверка, что мастер назначен на эту заявку
	var assignedMasterID *int
	err := pool.QueryRow(ctx, "SELECT master_id FROM requests WHERE request_id = $1", requestID).Scan(&assignedMasterID)
	if err != nil {
		return err
	}

	if assignedMasterID == nil || *assignedMasterID != masterID {
		return fmt.Errorf("можно комментировать только свои заявки")
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO comments (request_id, master_id, message) 
		VALUES ($1, $2, $3)
	`, requestID, masterID, message)

	return err
}

// Получить всех мастеров
func GetAllMasters(ctx context.Context, pool *pgxpool.Pool) ([]User, error) {
	query := `
		SELECT user_id, fio, phone, login, type 
		FROM users 
		WHERE type = $1
		ORDER BY fio
	`

	rows, err := pool.Query(ctx, query, RoleMaster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var masters []User
	for rows.Next() {
		var u User
		err := rows.Scan(&u.UserID, &u.FIO, &u.Phone, &u.Login, &u.Type)
		if err != nil {
			return nil, err
		}
		masters = append(masters, u)
	}

	return masters, nil
}

// ============ СТАТИСТИКА ============

type Statistics struct {
	CompletedRequests     int               `json:"completed_requests"`
	AverageCompletionTime float64           `json:"average_completion_days"`
	ProblemTypeStats      []ProblemTypeStat `json:"problem_type_stats"`
	MasterStats           []MasterStat      `json:"master_stats"`
}

type ProblemTypeStat struct {
	ProblemType string  `json:"problem_type"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
}

type MasterStat struct {
	MasterID           int     `json:"master_id"`
	MasterName         string  `json:"master_name"`
	CompletedRequests  int     `json:"completed_requests"`
	InProgressRequests int     `json:"in_progress_requests"`
	AverageTime        float64 `json:"average_completion_days"`
}

// Получить общую статистику
func GetStatistics(ctx context.Context, pool *pgxpool.Pool) (*Statistics, error) {
	stats := &Statistics{}

	// 1. Количество выполненных заявок
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM requests 
		WHERE request_status = 'Выполнена'
	`).Scan(&stats.CompletedRequests)
	if err != nil {
		return nil, err
	}

	// 2. Среднее время выполнения заявки (в днях)
	err = pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (completion_date - start_date))/86400), 0)
		FROM requests 
		WHERE request_status = 'Выполнена' 
		  AND completion_date IS NOT NULL
	`).Scan(&stats.AverageCompletionTime)
	// Postgres date subtraction gives days by default, but safe to be explicit or casting.
	// Actually `completion_date - start_date` returns `integer` days if both are DATE.
	// But in DB struct they are DATE. `time.Time` in struct.
	// Let's assume standard postgres subtraction.
	if err != nil {
		// Try simpler approach for average days if EXTRACT fails or types mismatch
		return nil, err
	}

	// 3. Статистика по типам неисправностей (первое слово)
	rows, err := pool.Query(ctx, `
		SELECT 
			SPLIT_PART(problem_description, ' ', 1) as problem_type,
			COUNT(*) as count,
			ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
		FROM requests
		WHERE request_status = 'Выполнена'
		GROUP BY problem_type
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var stat ProblemTypeStat
		err := rows.Scan(&stat.ProblemType, &stat.Count, &stat.Percentage)
		if err != nil {
			return nil, err
		}
		stats.ProblemTypeStats = append(stats.ProblemTypeStats, stat)
	}

	// 4. Статистика по мастерам
	rows3, err := pool.Query(ctx, `
		SELECT 
			u.user_id,
			u.fio,
			COUNT(CASE WHEN r.request_status = 'Выполнена' THEN 1 END) as completed,
			COUNT(CASE WHEN r.request_status = 'В процессе ремонта' THEN 1 END) as in_progress,
			COALESCE(AVG(CASE 
				WHEN r.request_status = 'Выполнена' AND r.completion_date IS NOT NULL 
				THEN r.completion_date - r.start_date 
			END), 0) as avg_time
		FROM users u
		LEFT JOIN requests r ON u.user_id = r.master_id
		WHERE u.type = $1
		GROUP BY u.user_id, u.fio
		ORDER BY completed DESC
	`, RoleMaster)
	if err != nil {
		return nil, err
	}
	defer rows3.Close()

	for rows3.Next() {
		var stat MasterStat
		err := rows3.Scan(
			&stat.MasterID,
			&stat.MasterName,
			&stat.CompletedRequests,
			&stat.InProgressRequests,
			&stat.AverageTime,
		)
		if err != nil {
			return nil, err
		}
		stats.MasterStats = append(stats.MasterStats, stat)
	}

	return stats, nil
}

// ============ HANDLERS ============

type Server struct {
	pool *pgxpool.Pool
}

// Middleware для аутентификации
func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Требуется авторизация"})
			c.Abort()
			return
		}

		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный формат токена"})
			c.Abort()
			return
		}
		tokenString := authHeader[7:]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Невалидный токен"})
			c.Abort()
			return
		}

		var user User
		err = s.pool.QueryRow(c.Request.Context(),
			"SELECT user_id, fio, phone, login, type FROM users WHERE user_id = $1",
			claims.UserID,
		).Scan(&user.UserID, &user.FIO, &user.Phone, &user.Login, &user.Type)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не найден"})
			c.Abort()
			return
		}

		c.Set("user", &user)
		c.Next()
	}
}

// POST /api/login - авторизация
func (s *Server) LoginHandler(c *gin.Context) {
	var input LoginRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	user, err := AuthenticateUser(c.Request.Context(), s.pool, input.Login, input.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать токен"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Авторизация успешна",
		"user":    user,
		"token":   token,
	})
}

// GET /api/requests - получить все заявки
func (s *Server) GetRequestsHandler(c *gin.Context) {
	user, _ := c.Get("user")
	userObj := user.(*User)

	requests, err := GetAllRequests(c.Request.Context(), s.pool, userObj)
	if err != nil {
		log.Printf("Ошибка получения заявок: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить заявки"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"requests": requests,
		"count":    len(requests),
	})
}

// GET /api/requests/:id - получить заявку по ID
func (s *Server) GetRequestByIDHandler(c *gin.Context) {
	user, _ := c.Get("user")
	userObj := user.(*User)

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}

	request, err := GetRequestByID(c.Request.Context(), s.pool, id, userObj)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения заявки"})
		return
	}

	if request == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Заявка не найдена"})
		return
	}

	c.JSON(http.StatusOK, request)
}

// POST /api/requests - создать заявку
func (s *Server) CreateRequestHandler(c *gin.Context) {
	user, _ := c.Get("user")
	userObj := user.(*User)

	if userObj.Type != RoleClient {
		c.JSON(http.StatusForbidden, gin.H{"error": "Только клиенты могут создавать заявки"})
		return
	}

	var input CreateRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные: " + err.Error()})
		return
	}

	input.ClientID = userObj.UserID

	requestID, err := CreateRequest(c.Request.Context(), s.pool, input)
	if err != nil {
		log.Printf("Ошибка создания заявки: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать заявку"})
		return
	}

	request, _ := GetRequestByID(c.Request.Context(), s.pool, requestID, userObj)
	c.JSON(http.StatusCreated, request)
}

// PUT /api/requests/:id - обновить заявку
func (s *Server) UpdateRequestHandler(c *gin.Context) {
	user, _ := c.Get("user")
	userObj := user.(*User)

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}

	var input UpdateRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	err = UpdateRequest(c.Request.Context(), s.pool, id, input, userObj)
	if err != nil {
		log.Printf("Ошибка обновления заявки: %v", err)
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	request, _ := GetRequestByID(c.Request.Context(), s.pool, id, userObj)
	c.JSON(http.StatusOK, request)
}

// POST /api/requests/:id/assign-master - назначить мастера
func (s *Server) AssignMasterHandler(c *gin.Context) {
	user, _ := c.Get("user")
	userObj := user.(*User)

	if userObj.Type != RoleManager && userObj.Type != RoleOperator {
		c.JSON(http.StatusForbidden, gin.H{"error": "Только менеджеры и операторы могут назначать мастеров"})
		return
	}

	requestID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID заявки"})
		return
	}

	var input AssignMasterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	err = AssignMasterToRequest(c.Request.Context(), s.pool, requestID, input.MasterID)
	if err != nil {
		log.Printf("Ошибка назначения мастера: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	request, _ := GetRequestByID(c.Request.Context(), s.pool, requestID, userObj)
	c.JSON(http.StatusOK, gin.H{
		"message": "Мастер успешно назначен",
		"request": request,
	})
}

// POST /api/requests/:id/comments - добавить комментарий
func (s *Server) AddCommentHandler(c *gin.Context) {
	user, _ := c.Get("user")
	userObj := user.(*User)

	if userObj.Type != RoleMaster {
		c.JSON(http.StatusForbidden, gin.H{"error": "Только мастера могут оставлять комментарии"})
		return
	}

	requestID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID заявки"})
		return
	}

	var input CreateCommentInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}

	err = AddComment(c.Request.Context(), s.pool, requestID, userObj.UserID, input.Message)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Комментарий добавлен"})
}

// GET /api/masters - получить всех мастеров
func (s *Server) GetMastersHandler(c *gin.Context) {
	masters, err := GetAllMasters(c.Request.Context(), s.pool)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить мастеров"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"masters": masters,
		"count":   len(masters),
	})
}

// GET /api/statistics - получить статистику
func (s *Server) GetStatisticsHandler(c *gin.Context) {
	stats, err := GetStatistics(c.Request.Context(), s.pool)
	if err != nil {
		log.Printf("Ошибка получения статистики: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить статистику"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// ============ MAIN ============
func main() {
	ctx := context.Background()

	// Connect to postgres DB 'repair_service'
	pool, err := pgxpool.New(ctx, "postgres://postgres:zxcqwe123@localhost:5432/repair_service")
	if err != nil {
		log.Fatalf("Не удалось создать пул соединений: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("Не удалось подключиться к БД: %v", err)
	}

	server := &Server{pool: pool}
	r := gin.Default()

	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	r.Use(cors.New(corsConfig))

	api := r.Group("/api")
	{
		api.POST("/login", server.LoginHandler)

		protected := api.Group("")
		protected.Use(server.AuthMiddleware())
		{
			protected.GET("/requests", server.GetRequestsHandler)
			protected.GET("/requests/:id", server.GetRequestByIDHandler)
			protected.POST("/requests", server.CreateRequestHandler)
			protected.PUT("/requests/:id", server.UpdateRequestHandler)
			protected.POST("/requests/:id/assign-master", server.AssignMasterHandler)
			protected.POST("/requests/:id/comments", server.AddCommentHandler)
			protected.GET("/masters", server.GetMastersHandler)
			protected.GET("/statistics", server.GetStatisticsHandler)
		}
	}

	log.Println("Сервер запущен на :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
