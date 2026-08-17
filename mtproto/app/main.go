package main

import (
    //"encoding/json"
    "fmt"
    "log"
    "io"
    "time"
    "os"
    "os/signal"
    "syscall"
    "bytes"
    "bufio"
    "strconv"
    "strings"
    //"context"
    //"net"
    "net/url"
    "net/http"
    "encoding/json"

    "github.com/go-git/go-billy/v6/memfs"
    "github.com/go-git/go-git/v6"
    "github.com/go-git/go-git/v6/storage/memory"

    "github.com/xtls/xray-core/core"
    _ "github.com/xtls/xray-core/main/json"
    _ "github.com/xtls/xray-core/app/proxyman/inbound"
    //_ "github.com/xtls/xray-core/main/distro/all"
)

// Структуры для генерации минимального JSON-конфига
type XrayConfig struct {
    Inbounds  []Inbound  `json:"inbounds"`
    Outbounds []Outbound `json:"outbounds"`
}

type Inbound struct {
    Protocol string `json:"protocol"`
    Port     int    `json:"port"`
    Listen   string `json:"listen"`
}

type Outbound struct {
    Protocol      string         `json:"protocol"`
    Settings      VlessSettings  `json:"settings"`
    StreamSettings StreamSettings `json:"streamSettings"`
}

type VlessSettings struct {
    Vnext []Vnext `json:"vnext"`
}

type Vnext struct {
    Address string `json:"address"`
    Port    int    `json:"port"`
    Users   []User `json:"users"`
}

type User struct {
    ID       string `json:"id"`
    Encryption string `json:"encryption"`
    Flow     string `json:"flow,omitempty"`
}

type StreamSettings struct {
    Network  string        `json:"network"`
    Security string        `json:"security"`
    Reality  *RealitySpecs `json:"realitySettings,omitempty"`
}

type RealitySpecs struct {
    Show       bool   `json:"show"`
    ServerName string `json:"serverName"`
    PublicKey  string `json:"publicKey"`
    ShortID    string `json:"shortId"`
    Fingerprint string `json:"fingerprint"`
}

func readRepoFile(repoURL, targetFile string) ([]byte, error) {
    fmt.Println("Клонирование репозитория в память...")

    // Инициализируем виртуальную файловую систему и хранилище в ОЗУ
    fs := memfs.New()
    storer := memory.NewStorage()

    // Клонируем только последний коммит (Depth: 1) для экономии памяти
    repo, err := git.Clone(storer, fs, &git.CloneOptions{
        URL:   repoURL,
        Depth: 1, 
    })
    if err != nil {
        return nil, err
    }

    // Получаем рабочую копию (Worktree) из памяти
    wt, err := repo.Worktree()
    if err != nil {
        return nil, err
    }

    // Открываем файл из виртуальной файловой системы
    file, err := wt.Filesystem().Open(targetFile)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    // Читаем содержимое файла
    content, err := io.ReadAll(file)
    if err != nil {
        return nil, err
    }

    return content, nil
}

// Функция конвертации vless:// в JSON байты
func parseVlessToStruct(vlessLink string) (XrayConfig, error) {
    u, err := url.Parse(vlessLink)
    if err != nil || u.Scheme != "vless" {
        return XrayConfig{}, fmt.Errorf("неверный формат ссылки: %v", err)
    }

    // Извлекаем UUID и Host/Port
    uuid := u.User.Username()
    host := u.Hostname()
    port, _ := strconv.Atoi(u.Port())

    // Извлекаем Query параметры
    q := u.Query()
    security := q.Get("security")
    parsedFlow := q.Get("flow")
    network := q.Get("type")
    if network == "" {
        network = "tcp" // по умолчанию TCP
    }

    // Собираем структуру Outbound
    user := User{
        ID:         uuid,
        Encryption: "none",
        Flow:       parsedFlow,
    }

    vnext := Vnext{
        Address: host,
        Port:    port,
        Users:   []User{user},
    }

    outbound := Outbound{
        Protocol: "vless",
        Settings: VlessSettings{Vnext: []Vnext{vnext}},
        StreamSettings: StreamSettings{
            Network:  network,
            Security: security,
        },
    }

    // Настройка REALITY (если используется)
    if security == "reality" {
        outbound.StreamSettings.Reality = &RealitySpecs{
            Show:        false,
            ServerName:  q.Get("sni"),
            PublicKey:   q.Get("pbk"),
            ShortID:     q.Get("sid"),
            Fingerprint: q.Get("fp"),
        }
    }

    // Создаем локальный Socks-инбаунд для клиента
    localInbound := Inbound{
        Protocol: "socks",
        Port:     8080, // порт вашего локального прокси
        Listen:   "127.0.0.1",
    }

    config := XrayConfig{
        Inbounds:  []Inbound{localInbound},
        Outbounds: []Outbound{outbound},
    }

    return config, nil
}

func serverStart(jsonConfig []byte) (*core.Instance, error) {
    // 1. Получаем JSON с настройками сети
    //configJson := makeClientConfigJson()

    // 2. Читаем конфигурацию через парсер Xray
    xrayConfig, err := core.LoadConfig("json", bytes.NewReader(jsonConfig))
    if err != nil {
        //log.Fatalf("[error] ошибка обработки конфигурации Xray: %v", err)
        return nil, err
    }

    // 3. Инициализируем и запускаем экземпляр Xray туннеля
    server, err := core.New(xrayConfig)
    if err != nil {
        //log.Fatalf("[error] ошибка инициализации ядра Xray: %v", err)
        return nil, err
    }

    if err := server.Start(); err != nil {
        //log.Fatalf("[error] не удалось запустить туннель: %v", err)
        return nil, err
    }

    fmt.Println("🚀 VLESS туннель успешно поднят!")
    fmt.Println("📍 Локальный SOCKS5 прокси запущен на 127.0.0.1:8080")

    return server, nil
}

func checkProxy(socksAddr string) error {
    time.Sleep(500 * time.Millisecond)
	fmt.Println("⏳ Проверка прокси...")

	// 1. Парсим адрес локального прокси Xray
	proxyURL, err := url.Parse("socks5h://127.0.0.1:8080")
	if err != nil {
		//fmt.Printf("❌ Ошибка парсинга URL прокси: %v\n", err)
		return err
	}

	// 2. Настраиваем стандартный транспорт через поле Proxy
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL), // Передаем адрес сюда
		TLSHandshakeTimeout: 4 * time.Second,
	}

    // 3. Создаем клиент с общим таймаутом в 7 секунд
    client := &http.Client{
        Transport: transport,
        Timeout:   7 * time.Second,
    }

    // 4. Делаем тестовый запрос (узнаем наш IP через прокси)
    resp, err := client.Get("https://telegram.org/")
    if err != nil {
        //fmt.Printf("❌ Прокси НЕ работает. Ошибка: %v\n", err)
        return err
    }
    defer resp.Body.Close()

    // 5. Читаем ответ сайта
    if _, err := io.ReadAll(resp.Body); err != nil {
        //fmt.Printf("❌ Не удалось прочитать ответ сервера: %v\n", err)
        return err
    }

    fmt.Printf("✅ Прокси %s работает!\n", socksAddr)

    return nil
}

func main() {
    go func(){
        for {
            content, err := readRepoFile("https://github.com/igareck/vpn-configs-for-russia.git", "BLACK_VLESS_RUS.txt")
            if err != nil {
                log.Printf("[error] не удалось скопировать репозиторий: %v", err)
                time.Sleep(30 * time.Second)
                continue
            } 
            
            scanner := bufio.NewScanner(bytes.NewReader(content))
            for scanner.Scan() {
                line := scanner.Bytes() // тип []byte
                if strings.HasPrefix(string(line), "vless://") {
                    fmt.Printf("Строка: %s\n", string(line))
                    config, err := parseVlessToStruct(string(line))
                    if err != nil {
                        log.Printf("[error] %v", err)
                    } else {
                        //log.Printf("[debug] %v", string(data))
						data, err := json.MarshalIndent(config, "", "  ")
						if err != nil {
                            log.Printf("[error] %v", err)
                            continue
                        }
                        server, err := serverStart(data)
                        if err != nil {
                            log.Printf("[error] %v", err)
                            continue
                        }
                        if err := checkProxy("127.0.0.1:8080"); err != nil {
                            server.Close()
                            log.Printf("[error] %v", err)
                            continue
                        }
						log.Printf("[debug] прокси запущен: %v", config.Outbounds[0].Settings.Vnext[0].Address)
                        break
                        //os.Exit(0)
                    }
                }
            }

            time.Sleep(300 * time.Second)
        }
    }()

    // Ожидаем сигнала прерывания (Ctrl+C) для корректного закрытия
    osSignals := make(chan os.Signal, 1)
    signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
    <-osSignals

    //server.Close()
    //fmt.Println("Туннель остановлен.")
}
