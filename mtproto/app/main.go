package main

import (
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
    "context"
    "net"
    "net/url"
    "net/http"
    "encoding/json"

    "golang.org/x/net/proxy"

    "github.com/xtls/xray-core/core"
    _ "github.com/xtls/xray-core/main/json"
    _ "github.com/xtls/xray-core/app/proxyman/inbound"
    
    "github.com/9seconds/mtg/v2/mtglib"
    "github.com/9seconds/mtg/v2/network"
    "github.com/9seconds/mtg/v2/antireplay"
    "github.com/9seconds/mtg/v2/ipblocklist"
    "github.com/9seconds/mtg/v2/ipblocklist/files"
    "github.com/9seconds/mtg/v2/events"
    "github.com/9seconds/mtg/v2/logger"
    "github.com/yl2chen/cidranger"
    "github.com/9seconds/mtg/v2/essentials"
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

func readHttpFile(url string) ([]byte, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    return body, nil
}

// Функция конвертации vless:// в JSON байты
func parseVlessToStruct(vlessLink string) (XrayConfig, error) {
    u, err := url.Parse(vlessLink)
    if err != nil || u.Scheme != "vless" {
        return XrayConfig{}, fmt.Errorf("Неверный формат ссылки: %v", err)
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
        Port:     10808, // порт вашего локального прокси
        Listen:   "127.0.0.1",
    }

    config := XrayConfig{
        Inbounds:  []Inbound{localInbound},
        Outbounds: []Outbound{outbound},
    }

    return config, nil
}

func proxyStart(jsonConfig []byte) (*core.Instance, error) {
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

    log.Print("[Info] 🚀 VLESS туннель успешно поднят!")
    log.Print("[Info] 📍 Локальный SOCKS5 прокси запущен на 127.0.0.1:10808")

    return server, nil
}

func proxyCheck(socksAddr string) error {
    time.Sleep(500 * time.Millisecond)
    log.Print("[Info] ⏳ Проверка прокси...")

    // 1. Парсим адрес локального прокси Xray
    proxyURL, err := url.Parse("socks5h://127.0.0.1:10808")
    if err != nil {
        return err
    }

    // 2. Настраиваем стандартный транспорт через поле Proxy
    transport := &http.Transport{
        Proxy:               http.ProxyURL(proxyURL), // Передаем адрес сюда
        TLSHandshakeTimeout: 10 * time.Second,
    }

    // 3. Создаем клиент с общим таймаутом в 7 секунд
    client := &http.Client{
        Transport: transport,
        Timeout:   10 * time.Second,
    }

    // 4. Делаем тестовый запрос 
    resp, err := client.Get("https://telegram.org/")
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // 5. Читаем ответ сайта
    if _, err := io.ReadAll(resp.Body); err != nil {
        return err
    }

    log.Printf("[Info] ✅ Прокси %s работает!", socksAddr)

    return nil
}

// 1. Обновленный адаптер, который теперь поддерживает методы Dial и DialContext
type socksAdapter struct {
    // Используем ContextDialer, чтобы прокидывать таймауты из mtg в SOCKS5
    socksDialer proxy.ContextDialer
}

// Реализуем метод Dial (вызывает DialContext с пустым контекстом)
func (a socksAdapter) Dial(netw, address string) (essentials.Conn, error) {
    return a.DialContext(context.Background(), netw, address)
}

// Реализуем обязательный метод DialContext, который требовал компилятор
func (a socksAdapter) DialContext(ctx context.Context, netw, address string) (essentials.Conn, error) {
    // Делаем вызов через наш SOCKS5 прокси с поддержкой контекста
    conn, err := a.socksDialer.DialContext(ctx, netw, address)
    if err != nil {
        return nil, err
    }
    
    // Используем внутреннюю функцию mtg для обертки сокета
    return essentials.WrapNetConn(conn), nil
}

func serverStart() {
    
}

func main() {
    list := []string{
        "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
        "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    }
    
    for _, l := range list {
        content, err := readHttpFile(l)
        if err != nil {
            log.Printf("[Error] Не удалось прочитать файл: %v", err)
            continue
        } 
        
        scanner := bufio.NewScanner(bytes.NewReader(content))
        for scanner.Scan() {
            line := scanner.Bytes() // тип []byte
            if strings.HasPrefix(string(line), "vless://") {
                log.Printf("[Info] Строка: %s\n", string(line))
                config, err := parseVlessToStruct(string(line))
                if err != nil {
                    log.Printf("[Error] %v", err)
                } else {
                    //log.Printf("[Info] %v", string(data))
                    data, err := json.MarshalIndent(config, "", "  ")
                    if err != nil {
                        log.Printf("[Error] %v", err)
                        continue
                    }
                    proxy, err := proxyStart(data)
                    if err != nil {
                        log.Printf("[Error] %v", err)
                        continue
                    }
                    if err := proxyCheck("127.0.0.1:10808"); err != nil {
                        proxy.Close()
                        log.Printf("[Error] %v", err)
                        continue
                    }
                    log.Printf("[Info] Прокси запущен: %v", config.Outbounds[0].Settings.Vnext[0].Address)
                    break
                    //os.Exit(0)
                }
            }
        }
    }

    baseDialer := &net.Dialer{
        Timeout:   15 * time.Second,
        KeepAlive: 30 * time.Second,
    }

    // Создаем базовый SOCKS5 диалер
    rawSocksDialer, err := proxy.SOCKS5("tcp", "127.0.0.1:10808", nil, baseDialer)
    if err != nil {
        log.Fatalf("[Error] %v", err)
    }

    // 2. Принудительно приводим к интерфейсу proxy.ContextDialer
    contextDialer, ok := rawSocksDialer.(proxy.ContextDialer)
    if !ok {
        log.Fatalf("[Error] Созданный SOCKS5 dialer не поддерживает ContextDialer")
    }

    // 3. Инициализируем наш адаптер
    socksDialer := socksAdapter{socksDialer: contextDialer}
    
    // 5. Инициализируем сетевой слой MTG.
    ntw, err := network.NewNetwork(socksDialer, "mtgtest", "1.1.1.1", 0)
    if err != nil {
        log.Fatalf("[Error] Не удалось создать сетевой слой ntw: %v", err)
    }

    //secret := mtglib.GenerateSecret("httpbin.org")
    //log.Printf("[Info] secret: %v", secret)

    allowlist, _ := ipblocklist.NewFireholFromFiles(
        logger.NewNoopLogger(),
        1,
        []files.File{
            files.NewMem([]*net.IPNet{
                cidranger.AllIPv4,
                cidranger.AllIPv6,
            }),
        },
        nil,
    )

    go allowlist.Run(time.Second)

    str := "7nthKohRGKURORpq9bRTyh5odHRwYmluLm9yZw"
    key := [16]byte{}
    copy(key[:], str)
    log.Printf("[Info] secret: %v", str)

    // Готовим правильную конфигурацию для mtglib.Proxy
    proxyOpts := mtglib.ProxyOpts{
        Secret:         mtglib.Secret{
            Key: key,
            Host: "httpbin.org",
        },
        Network:         ntw, // Передаем корректно созданный сетевой стек
        AntiReplayCache: antireplay.NewNoop(),
        IPBlocklist:     ipblocklist.NewNoop(),
        IPAllowlist:     allowlist,
        EventStream:     events.NewNoopStream(),
        Logger:          logger.NewNoopLogger(),
    }

    proxy, err := mtglib.NewProxy(proxyOpts)
    if err != nil {
        log.Fatalf("Не удалось создать MTProto прокси: %v", err)
    }

    // Слушаем входящий порт для Telegram
    listener, err := net.Listen("tcp", "0.0.0.0:8080")
    if err != nil {
        log.Fatalf("Не удалось открыть порт 8080 для MTProto: %v", err)
    }
    defer listener.Close()
    
    // Обрабатываем новые подключения через встроенный в mtglib менеджер сессий
    go func(){
        err := proxy.Serve(listener)
        if err != nil {
            log.Fatalf("Не удалось создать MTProto прокси: %v", err)
        }
        log.Printf("[MTProto] Сервер ожидает подключений Telegram на порту 8080")
    }()

    // Ожидаем сигнала прерывания (Ctrl+C) для корректного закрытия
    osSignals := make(chan os.Signal, 1)
    signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
    <-osSignals

    //server.Close()
    //fmt.Println("Туннель остановлен.")
}
