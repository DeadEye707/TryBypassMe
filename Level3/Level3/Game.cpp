#include "AntiCheat.h"
#include <mmsystem.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <random>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

// ============================================================
// CONSTANTS
// ============================================================
static const int   SCREEN_W = 1024;
static const int   SCREEN_H = 768;
static const int   TILE_SIZE = 48;
static const float PI_F = 3.14159265f;
static const float PLAYER_SPEED = 220.0f;
static const float BULLET_SPEED = 650.0f;
static const float SHOOT_COOLDOWN = 0.15f;
static const int   PLAYER_MAX_HP = 100;
static const int   PLAYER_MAX_AMMO = 30;
static const float RELOAD_TIME = 1.5f;
static const float POWER_WEAPON_DURATION = 10.0f;

// ============================================================
//  MATH
// ============================================================
struct Vec2 {
    float x, y;
    Vec2(float x = 0, float y = 0) : x(x), y(y) {}
    Vec2 operator+(const Vec2& o) const { return { x + o.x, y + o.y }; }
    Vec2 operator-(const Vec2& o) const { return { x - o.x, y - o.y }; }
    Vec2 operator*(float s)       const { return { x * s,   y * s }; }
    Vec2& operator+=(const Vec2& o) { x += o.x; y += o.y; return *this; }
    float len()  const { return sqrtf(x * x + y * y); }
    Vec2  norm() const { float l = len(); return l > 0 ? Vec2{ x / l, y / l } : Vec2{}; }
    float dot(const Vec2& o) const { return x * o.x + y * o.y; }
};

static float randf(float lo, float hi) {
    return lo + (float)rand() / (float)RAND_MAX * (hi - lo);
}

// ============================================================
// ENTITY STRUCTS
// ============================================================
struct Bullet {
    Vec2  pos, vel;
    bool  active = false;
    bool  fromPlayer = true;
    float radius = 5.0f;
    int   damage = 15;
};

struct Enemy {
    Vec2  pos;
    float radius = 18.0f;
    int   hp = 60;
    int   maxHp = 60;
    float shootCd = 0.0f;
    float speed = 0.0f;
    bool  alive = true;
    int   type = 0;
};

struct Particle {
    Vec2     pos, vel;
    float    life = 0.f;
    float    maxLife = 0.f;
    COLORREF color = 0;
    float    size = 0.f;
    bool     active = false;
};

struct FloatingText {
    Vec2        pos;
    std::string text;
    float       life = 0.f;
    COLORREF    color = 0;
    bool        active = false;
};

enum DropType { DROP_HEALTH = 0, DROP_AMMO = 1, DROP_WEAPON = 2 };

struct Drop {
    Vec2     pos;
    DropType type = DROP_HEALTH;
    float    radius = 18.0f;
    float    lifetime = 10.0f;
    bool     active = false;
    int      weaponId = 0;
    float    pulseT = 0.0f;
};

// ============================================================
// GAME STATE
// ============================================================
static Vec2  g_playerPos = { SCREEN_W / 2.f, SCREEN_H / 2.f };
static float g_playerAngle = 0.f;

static float g_shootCd = 0.f;
static float g_reloadCd = 0.f;
static bool  g_reloading = false;

static std::vector<Enemy>        g_enemies;
static std::vector<Bullet>       g_bullets;
static std::vector<Particle>     g_particles;
static std::vector<FloatingText> g_floatTexts;
static std::vector<Drop>         g_drops;

static int   g_powerWeaponId = 0;
static float g_powerWeaponTimer = 0.f;

static float g_waveTimer = 0.f;
static float g_waveDelay = 3.f;
static bool  g_waveSpawning = false;
static int   g_enemiesToSpawn = 0;
static float g_spawnTimer = 0.f;
static float g_totalTime = 0.f;
static int   g_highScore = 0;

static bool  g_keys[256] = {};
static bool  g_mouseLeft = false;
static POINT g_mousePos = { SCREEN_W / 2, SCREEN_H / 2 };

static HWND    g_hwnd = nullptr;
static HDC     g_hdc = nullptr;
static HBITMAP g_hbmp = nullptr;
static HDC     g_memDC = nullptr;
static int     g_fps = 0;

// ============================================================
// PARTICLES AND FLOATING TEXT
// ============================================================
static void SpawnParticles(Vec2 pos, COLORREF col, int count, float speed, float life)
{
    for (int i = 0; i < count; i++)
        for (auto& p : g_particles)
            if (!p.active) {
                float a = randf(0, 2 * PI_F), s = randf(speed * .3f, speed);
                p.pos = pos; p.vel = { cosf(a) * s, sinf(a) * s };
                p.life = p.maxLife = randf(life * .5f, life);
                p.color = col; p.size = randf(2.f, 5.f); p.active = true;
                break;
            }
}

static void SpawnFloatText(Vec2 pos, const std::string& text, COLORREF col)
{
    for (auto& f : g_floatTexts)
        if (!f.active) {
            f.pos = pos; f.text = text; f.color = col;
            f.life = 1.2f; f.active = true;
            return;
        }
}

// ============================================================
//  WAVE SYSTEM
// ============================================================
static void StartWave(int wave)
{
    g_enemiesToSpawn = 5 + wave * 3;
    g_waveSpawning = true;
    g_spawnTimer = 0.f;
    g_waveTimer = 0.f;
    char buf[32];
    sprintf_s(buf, skStr("WAVE %d"), wave);
    SpawnFloatText({ SCREEN_W / 2.f, SCREEN_H / 2.f - 60.f }, buf, RGB(255, 220, 0));
}

static void SpawnEnemy(int wave)
{
    Enemy e;
    int side = rand() % 4;
    switch (side) {
    case 0: e.pos = { randf(0, SCREEN_W), -30.f };           break;
    case 1: e.pos = { randf(0, SCREEN_W), SCREEN_H + 30.f }; break;
    case 2: e.pos = { -30.f, randf(0, SCREEN_H) };           break;
    case 3: e.pos = { SCREEN_W + 30.f, randf(0, SCREEN_H) }; break;
    }
    float r = randf(0, 1);
    if (wave < 3 || r < 0.5f) {
        e.type = 0; e.hp = e.maxHp = 50; e.speed = randf(70, 110);
    }
    else if (r < 0.8f) {
        e.type = 1; e.hp = e.maxHp = 40; e.speed = randf(55, 85);
        e.shootCd = randf(1.5f, 3.f);
    }
    else {
        e.type = 2; e.hp = e.maxHp = 150; e.speed = randf(40, 60);
        e.radius = 26.f;
    }
    e.speed += wave * 4.f;
    e.alive = true;
    g_enemies.push_back(e);
}

// ============================================================
// COLLISION
// ============================================================
static bool CircleCollide(Vec2 a, float ra, Vec2 b, float rb) {
    Vec2 d = a - b;
    return d.dot(d) < (ra + rb) * (ra + rb);
}

// ============================================================
// DAMAGE HELPER
// ============================================================
static void DealDamageToPlayer(int dmg)
{
    int hp = ACReadEnc(g_encHp);
    if (hp <= 0) return;
    hp -= dmg;
    g_totalDamageDealt_add(dmg);   // encrypted counter
    if (hp <= 0) {
        hp = 0;
        ACGameOverSet(true);
        g_highScore = std::max(g_highScore, ACReadEnc(g_encScore));
    }
    ACWriteEnc(g_encHp, hp);
}

// ============================================================
// UPDATE
// ============================================================
static void Update(float dt)
{
    ACTick();

    if (g_gameOver || g_paused) return;
    g_totalTime += dt;

    // Player movement
    Vec2 dir = {};
    if (g_keys['W'] || g_keys[VK_UP])    dir.y -= 1;
    if (g_keys['S'] || g_keys[VK_DOWN])  dir.y += 1;
    if (g_keys['A'] || g_keys[VK_LEFT])  dir.x -= 1;
    if (g_keys['D'] || g_keys[VK_RIGHT]) dir.x += 1;
    dir = dir.norm();
    g_playerPos += dir * (PLAYER_SPEED * dt);
    g_playerPos.x = std::max(20.f, std::min((float)SCREEN_W - 20.f, g_playerPos.x));
    g_playerPos.y = std::max(20.f, std::min((float)SCREEN_H - 20.f, g_playerPos.y));

    Vec2 tom = { (float)g_mousePos.x - g_playerPos.x,
                 (float)g_mousePos.y - g_playerPos.y };
    g_playerAngle = atan2f(tom.y, tom.x);

    // Reload
    if (g_reloading) {
        g_reloadCd -= dt;
        if (g_reloadCd <= 0.f) {
            int refill = PLAYER_MAX_AMMO - ACReadEnc(g_encAmmo);
            if (refill > 0) g_ammoRefilled_add(refill);
            ACWriteEnc(g_encAmmo, PLAYER_MAX_AMMO);
            g_reloading = false;
            SpawnFloatText(g_playerPos - Vec2(0, 40), skStr("RELOADED"), RGB(100, 255, 100));
        }
    }
    if (g_keys['R'] && !g_reloading && ACReadEnc(g_encAmmo) < PLAYER_MAX_AMMO) {
        g_reloading = true;
        g_reloadCd = RELOAD_TIME;
    }

    // Normal weapon fire
    g_shootCd -= dt;
    if (!g_powerWeapon && g_mouseLeft && g_shootCd <= 0.f
        && !g_reloading && ACReadEnc(g_encAmmo) > 0 && !g_gameOver)
    {
        g_shootCd = SHOOT_COOLDOWN;
        ACWriteEnc(g_encAmmo, ACReadEnc(g_encAmmo) - 1);
        g_shotsFired_add(1);
        g_ammoConsumed_add(1);

        Bullet* slot = nullptr;
        for (auto& b : g_bullets) if (!b.active) { slot = &b; break; }
        if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); }

        float sp = randf(-0.04f, 0.04f);
        slot->pos = g_playerPos;
        slot->vel = { cosf(g_playerAngle + sp) * BULLET_SPEED,
                            sinf(g_playerAngle + sp) * BULLET_SPEED };
        slot->active = true;
        slot->fromPlayer = true;
        slot->damage = 20;
        slot->radius = 5.f;

        SpawnParticles(
            g_playerPos + Vec2{ cosf(g_playerAngle) * 28, sinf(g_playerAngle) * 28 },
            RGB(255, 200, 50), 5, 150.f, 0.1f);

        if (ACReadEnc(g_encAmmo) == 0) { g_reloading = true; g_reloadCd = RELOAD_TIME; }
    }

    // Wave management
    int alive = 0;
    for (auto& e : g_enemies) if (e.alive) alive++;

    if (g_waveSpawning) {
        g_spawnTimer -= dt;
        if (g_spawnTimer <= 0.f && g_enemiesToSpawn > 0) {
            SpawnEnemy(ACReadEnc(g_encWave));
            g_enemiesToSpawn--;
            g_spawnTimer = randf(.3f, .7f);
        }
        if (g_enemiesToSpawn == 0) g_waveSpawning = false;
    }

    if (!g_waveSpawning && alive == 0) {
        g_waveTimer += dt;
        if (g_waveTimer >= g_waveDelay) {
            ACWriteEnc(g_encWave, ACReadEnc(g_encWave) + 1);
            StartWave(ACReadEnc(g_encWave));
            int hp = ACReadEnc(g_encHp);
            int bonus = 10;
            int actualBonus = std::min(bonus, PLAYER_MAX_HP - hp);
            ACWriteEnc(g_encHp, std::min(hp + bonus, PLAYER_MAX_HP));
            g_totalHealed_add(actualBonus);
            SpawnFloatText(g_playerPos - Vec2(0, 60),
                "+" + std::to_string(bonus) + " HP", RGB(80, 255, 80));
        }
    }

    // Enemy AI
    for (auto& e : g_enemies) {
        if (!e.alive) continue;
        e.pos += (g_playerPos - e.pos).norm() * (e.speed * dt);

        if (e.type == 1) {
            e.shootCd -= dt;
            if (e.shootCd <= 0.f) {
                e.shootCd = std::max(
                    randf(1.5f, 3.5f) - (ACReadEnc(g_encWave) * 0.1f), 0.6f);
                Bullet* slot = nullptr;
                for (auto& b : g_bullets) if (!b.active) { slot = &b; break; }
                if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); }
                slot->pos = e.pos;
                slot->vel = (g_playerPos - e.pos).norm() * 280.f;
                slot->active = true;
                slot->fromPlayer = false;
                slot->damage = 12;
                slot->radius = 6.f;
            }
        }

        if (CircleCollide(g_playerPos, 16.f, e.pos, e.radius)) {
            int dmg = (e.type == 2) ? 20 : 10;
            DealDamageToPlayer(dmg);
            g_playerPos += (g_playerPos - e.pos).norm() * 30.f;
            SpawnParticles(g_playerPos, RGB(255, 50, 50), 8, 200.f, .3f);
            SpawnFloatText(g_playerPos - Vec2(0, 40),
                "-" + std::to_string(dmg), RGB(255, 80, 80));
        }
    }

    // Bullet movement and hit detection
    for (auto& b : g_bullets) {
        if (!b.active) continue;
        b.pos += b.vel * dt;

        if (b.pos.x < -50 || b.pos.x > SCREEN_W + 50 ||
            b.pos.y < -50 || b.pos.y > SCREEN_H + 50)
        {
            b.active = false;
            continue;
        }

        if (b.fromPlayer) {
            for (auto& e : g_enemies) {
                if (!e.alive) continue;
                if (CircleCollide(b.pos, b.radius, e.pos, e.radius)) {
                    b.active = false;
                    e.hp -= b.damage;
                    SpawnParticles(b.pos, RGB(255, 100, 0), 6, 120.f, .25f);
                    SpawnFloatText(e.pos - Vec2(0, 20),
                        "-" + std::to_string(b.damage), RGB(255, 180, 50));
                    if (e.hp <= 0) {
                        e.alive = false;
                        ACWriteEnc(g_encKills, ACReadEnc(g_encKills) + 1);
                        int pts = (e.type == 2) ? 300 : (e.type == 1) ? 200 : 100;
                        pts += ACReadEnc(g_encWave) * 10;
                        ACWriteEnc(g_encScore, ACReadEnc(g_encScore) + pts);
                        SpawnParticles(e.pos, RGB(255, 60, 60), 16, 220.f, .6f);
                        SpawnFloatText(e.pos,
                            "+" + std::to_string(pts), RGB(255, 255, 50));

                        float dr = randf(0, 1);
                        Drop d;
                        d.pos = e.pos; d.active = true;
                        d.lifetime = 10.f; d.pulseT = 0.f;
                        if (dr < 0.05f) { d.type = DROP_WEAPON; d.weaponId = rand() % 3; g_drops.push_back(d); }
                        else if (dr < 0.13f) { d.type = DROP_HEALTH; g_drops.push_back(d); }
                        else if (dr < 0.25f) { d.type = DROP_AMMO;   g_drops.push_back(d); }
                    }
                    break;
                }
            }
        }
        else {
            if (CircleCollide(b.pos, b.radius, g_playerPos, 16.f)) {
                b.active = false;
                DealDamageToPlayer(b.damage);
                SpawnParticles(g_playerPos, RGB(255, 50, 50), 8, 180.f, .25f);
                SpawnFloatText(g_playerPos - Vec2(0, 40),
                    "-" + std::to_string(b.damage), RGB(255, 80, 80));
            }
        }
    }

    // Power weapon countdown
    if (g_powerWeapon) {
        g_powerWeaponTimer -= dt;
        if (g_powerWeaponTimer <= 0.f) {
            ACSetPowerWeapon(false);
            g_shootCd = 0.f;
            SpawnFloatText(g_playerPos - Vec2(0, 50), skStr("WEAPON EXPIRED"), RGB(255, 100, 50));
        }
    }

    // Drop lifetime, pulse, and pickup
    for (auto& d : g_drops) {
        if (!d.active) continue;
        d.lifetime -= dt;
        d.pulseT += dt * 3.0f;
        if (d.lifetime <= 0.f) { d.active = false; continue; }

        if (CircleCollide(g_playerPos, 20.f, d.pos, d.radius)) {
            d.active = false;
            if (d.type == DROP_HEALTH) {
                int heal = 30;
                int hp = ACReadEnc(g_encHp);
                int actualHeal = std::min(heal, PLAYER_MAX_HP - hp);
                ACWriteEnc(g_encHp, std::min(hp + heal, PLAYER_MAX_HP));
                g_totalHealed_add(actualHeal);
                SpawnFloatText(d.pos, "+" + std::to_string(heal) + " HP", RGB(80, 255, 80));
                SpawnParticles(d.pos, RGB(50, 255, 80), 10, 150.f, 0.5f);
            }
            else if (d.type == DROP_AMMO) {
                int refill = PLAYER_MAX_AMMO - ACReadEnc(g_encAmmo);
                if (refill > 0) g_ammoRefilled_add(refill);
                ACWriteEnc(g_encAmmo, PLAYER_MAX_AMMO);
                g_reloading = false;
                SpawnFloatText(d.pos, skStr("AMMO REFILLED"), RGB(100, 200, 255));
                SpawnParticles(d.pos, RGB(100, 180, 255), 10, 150.f, 0.5f);
            }
            else if (d.type == DROP_WEAPON) {
                ACSetPowerWeapon(true);
                g_powerWeaponId = d.weaponId;
                g_powerWeaponTimer = POWER_WEAPON_DURATION;
                g_shootCd = 0.f;
                char n0[32], n1[32], n2[32];
                strcpy_s(n0, skStr("SHOTGUN")); strcpy_s(n1, skStr("MINIGUN")); strcpy_s(n2, skStr("ROCKET LAUNCHER"));
                const char* names[] = { n0, n1, n2 };
                SpawnFloatText(d.pos,
                    std::string(skStr("GOT ")) + names[d.weaponId] + "!", RGB(255, 220, 50));
                SpawnParticles(d.pos, RGB(255, 200, 50), 20, 200.f, 0.8f);
            }
        }
    }

    // Power weapon fire
    if (g_powerWeapon && g_mouseLeft && g_shootCd <= 0.f && !g_gameOver) {
        if (g_powerWeaponId == 0) {         // Shotgun
            g_shootCd = 0.5f;
            // Power weapons don't consume normal ammo, don't increment counters
            for (int si = 0; si < 6; si++) {
                Bullet* slot = nullptr;
                for (auto& b : g_bullets) if (!b.active) { slot = &b; break; }
                if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); }
                float sp = randf(-0.35f, 0.35f);
                slot->pos = g_playerPos;
                slot->vel = { cosf(g_playerAngle + sp) * BULLET_SPEED * 0.8f,
                                    sinf(g_playerAngle + sp) * BULLET_SPEED * 0.8f };
                slot->active = true; slot->fromPlayer = true;
                slot->damage = 25; slot->radius = 6.f;
            }
            SpawnParticles(
                g_playerPos + Vec2{ cosf(g_playerAngle) * 28, sinf(g_playerAngle) * 28 },
                RGB(255, 140, 0), 10, 200.f, 0.15f);
        }
        else if (g_powerWeaponId == 1) {    // Minigun
            g_shootCd = 0.05f;
            // Power weapons don't consume normal ammo, don't increment counters
            Bullet* slot = nullptr;
            for (auto& b : g_bullets) if (!b.active) { slot = &b; break; }
            if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); }
            float sp = randf(-0.06f, 0.06f);
            slot->pos = g_playerPos;
            slot->vel = { cosf(g_playerAngle + sp) * BULLET_SPEED * 1.2f,
                                sinf(g_playerAngle + sp) * BULLET_SPEED * 1.2f };
            slot->active = true; slot->fromPlayer = true;
            slot->damage = 10; slot->radius = 4.f;
            SpawnParticles(
                g_playerPos + Vec2{ cosf(g_playerAngle) * 28, sinf(g_playerAngle) * 28 },
                RGB(255, 255, 100), 3, 100.f, 0.05f);
        }
        else if (g_powerWeaponId == 2) {    // Rocket Launcher
            g_shootCd = 0.8f;
            // Power weapons don't consume normal ammo, don't increment counters
            Bullet* slot = nullptr;
            for (auto& b : g_bullets) if (!b.active) { slot = &b; break; }
            if (!slot) { g_bullets.push_back({}); slot = &g_bullets.back(); }
            slot->pos = g_playerPos;
            slot->vel = { cosf(g_playerAngle) * 300.f, sinf(g_playerAngle) * 300.f };
            slot->active = true; slot->fromPlayer = true;
            slot->damage = 120; slot->radius = 14.f;
            SpawnParticles(
                g_playerPos + Vec2{ cosf(g_playerAngle) * 28, sinf(g_playerAngle) * 28 },
                RGB(255, 80, 20), 12, 250.f, 0.2f);
        }
    }

    // Particle physics
    for (auto& p : g_particles) {
        if (!p.active) continue;
        p.pos += p.vel * dt;
        p.vel = p.vel * (1.f - dt * 3.f);
        p.life -= dt;
        if (p.life <= 0) p.active = false;
    }

    // Floating text drift
    for (auto& f : g_floatTexts) {
        if (!f.active) continue;
        f.pos.y -= 55.f * dt;
        f.life -= dt;
        if (f.life <= 0) f.active = false;
    }
}

// ============================================================
// RENDERING HELPERS
// ============================================================
static void DrawCircle(HDC dc, int x, int y, int r, COLORREF fill, COLORREF outline) {
    HBRUSH br = CreateSolidBrush(fill);
    HPEN   pn = CreatePen(PS_SOLID, 2, outline);
    SelectObject(dc, br); SelectObject(dc, pn);
    Ellipse(dc, x - r, y - r, x + r, y + r);
    DeleteObject(br); DeleteObject(pn);
}

static void DrawRect(HDC dc, int x, int y, int w, int h, COLORREF fill) {
    HBRUSH br = CreateSolidBrush(fill);
    SelectObject(dc, br); SelectObject(dc, GetStockObject(NULL_PEN));
    Rectangle(dc, x, y, x + w, y + h);
    DeleteObject(br);
}

static void DrawText_(HDC dc, const char* txt, int x, int y,
    COLORREF col, int sz = 16, bool bold = false, bool center = false)
{
    HFONT f = CreateFontA(sz, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        ANTIALIASED_QUALITY, DEFAULT_PITCH, skStr("Arial"));
    SelectObject(dc, f);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, col);
    if (center) {
        SIZE s;
        GetTextExtentPoint32A(dc, txt, (int)strlen(txt), &s);
        x -= s.cx / 2;
    }
    TextOutA(dc, x, y, txt, (int)strlen(txt));
    DeleteObject(f);
}

static void DrawBar(HDC dc, int x, int y, int w, int h,
    float frac, COLORREF fill, COLORREF bg)
{
    DrawRect(dc, x, y, w, h, bg);
    int fw = (int)(w * std::max(0.f, std::min(1.f, frac)));
    if (fw > 0) DrawRect(dc, x, y, fw, h, fill);
    HPEN pn = CreatePen(PS_SOLID, 1, RGB(80, 80, 80));
    SelectObject(dc, pn); SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, x, y, x + w, y + h);
    DeleteObject(pn);
}

static void AlphaOverlay(HDC dc, BYTE alpha) {
    HDC     tmp = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, SCREEN_W, SCREEN_H);
    SelectObject(tmp, bmp);
    DrawRect(tmp, 0, 0, SCREEN_W, SCREEN_H, RGB(0, 0, 0));
    BLENDFUNCTION bf{ AC_SRC_OVER, 0, alpha, 0 };
    AlphaBlend(dc, 0, 0, SCREEN_W, SCREEN_H, tmp, 0, 0, SCREEN_W, SCREEN_H, bf);
    DeleteDC(tmp); DeleteObject(bmp);
}

// ============================================================
// RENDER
// ============================================================
static void RenderGame()
{
    HDC dc = g_memDC;
    DrawRect(dc, 0, 0, SCREEN_W, SCREEN_H, RGB(18, 22, 18));

    // Background grid
    HPEN gp = CreatePen(PS_SOLID, 1, RGB(28, 35, 28));
    SelectObject(dc, gp);
    for (int x = 0; x < SCREEN_W; x += TILE_SIZE) MoveToEx(dc, x, 0, nullptr), LineTo(dc, x, SCREEN_H);
    for (int y = 0; y < SCREEN_H; y += TILE_SIZE) MoveToEx(dc, 0, y, nullptr), LineTo(dc, SCREEN_W, y);
    DeleteObject(gp);

    // Particles
    for (auto& p : g_particles) {
        if (!p.active) continue;
        float t = p.life / p.maxLife;
        COLORREF c = RGB((int)(GetRValue(p.color) * t),
            (int)(GetGValue(p.color) * t),
            (int)(GetBValue(p.color) * t));
        int s = (int)(p.size * t); if (s < 1) s = 1;
        DrawRect(dc, (int)p.pos.x - s / 2, (int)p.pos.y - s / 2, s, s, c);
    }

    // Enemy projectiles
    for (auto& b : g_bullets)
        if (b.active && !b.fromPlayer)
            DrawCircle(dc, (int)b.pos.x, (int)b.pos.y, (int)b.radius,
                RGB(255, 80, 80), RGB(255, 30, 30));

    // Player projectiles
    for (auto& b : g_bullets)
        if (b.active && b.fromPlayer)
            DrawCircle(dc, (int)b.pos.x, (int)b.pos.y, (int)b.radius,
                RGB(255, 240, 80), RGB(255, 200, 30));

    // Enemies with HP bar
    for (auto& e : g_enemies) {
        if (!e.alive) continue;
        int ix = (int)e.pos.x, iy = (int)e.pos.y, ir = (int)e.radius;
        COLORREF fill, out;
        switch (e.type) {
        case 0:  fill = RGB(200, 40, 40);  out = RGB(255, 80, 80);   break;
        case 1:  fill = RGB(180, 60, 200); out = RGB(220, 100, 255); break;
        default: fill = RGB(40, 100, 200); out = RGB(80, 160, 255);  break;
        }
        DrawCircle(dc, ix, iy, ir, fill, out);
        DrawBar(dc, ix - ir, iy - ir - 8, ir * 2, 4,
            (float)e.hp / e.maxHp, RGB(50, 230, 50), RGB(60, 20, 20));
        const char* lbl = e.type == 1 ? "S" : (e.type == 2 ? "T" : "");
        if (lbl[0]) DrawText_(dc, lbl, ix, iy - 8, RGB(255, 255, 255), 12, true, true);
    }

    // Player
    if (!g_gameOver) {
        int px = (int)g_playerPos.x, py = (int)g_playerPos.y;
        DrawCircle(dc, px + 3, py + 3, 18, RGB(0, 0, 0), RGB(0, 0, 0));
        DrawCircle(dc, px, py, 18, RGB(50, 180, 255), RGB(100, 220, 255));
        HPEN bp = CreatePen(PS_SOLID, 6, RGB(80, 220, 255));
        SelectObject(dc, bp);
        MoveToEx(dc, px + (int)(cosf(g_playerAngle) * 14),
            py + (int)(sinf(g_playerAngle) * 14), nullptr);
        LineTo(dc, px + (int)(cosf(g_playerAngle) * 26),
            py + (int)(sinf(g_playerAngle) * 26));
        DeleteObject(bp);
        DrawCircle(dc, px, py, 5, RGB(255, 255, 255), RGB(200, 200, 200));
    }

    // Drops
    for (auto& d : g_drops) {
        if (!d.active) continue;
        if (d.lifetime < 3.0f && ((int)(d.lifetime * 6)) % 2 == 0) continue;
        float pulse = 0.15f * sinf(d.pulseT) + 0.85f;
        int   r = (int)(d.radius * pulse);
        int   ix = (int)d.pos.x, iy = (int)d.pos.y;
        COLORREF fill, outline;
        const char* label = "";
        switch (d.type) {
        case DROP_HEALTH: fill = RGB(40, 200, 60);  outline = RGB(100, 255, 100); label = "HP";  break;
        case DROP_AMMO:   fill = RGB(40, 100, 220); outline = RGB(100, 180, 255); label = "AMO"; break;
        case DROP_WEAPON:
            switch (d.weaponId) {
            case 0:  fill = RGB(220, 140, 0);  outline = RGB(255, 200, 50);  label = "SHG"; break;
            case 1:  fill = RGB(200, 50, 200); outline = RGB(255, 100, 255); label = "MG";  break;
            default: fill = RGB(220, 50, 50);  outline = RGB(255, 100, 80);  label = "RKT"; break;
            }
            break;
        }
        DrawCircle(dc, ix, iy, r, fill, outline);
        DrawText_(dc, label, ix, iy - 6, RGB(255, 255, 255), 11, true, true);
    }

    // Floating numbers
    for (auto& f : g_floatTexts) {
        if (!f.active) continue;
        float a = f.life > .3f ? 1.f : f.life / .3f;
        DrawText_(dc, f.text.c_str(), (int)f.pos.x, (int)f.pos.y,
            RGB((int)(GetRValue(f.color) * a),
                (int)(GetGValue(f.color) * a),
                (int)(GetBValue(f.color) * a)),
            15, true, true);
    }

    // HUD: HP
    {
        int hp = ACReadEnc(g_encHp);
        DrawText_(dc, "HP", 14, 14, RGB(150, 150, 150), 14);
        DrawBar(dc, 40, 14, 200, 18, (float)hp / PLAYER_MAX_HP,
            RGB(50, 220, 80), RGB(40, 20, 20));
        char hpstr[16]; sprintf_s(hpstr, "%d/%d", hp, PLAYER_MAX_HP);
        DrawText_(dc, hpstr, 248, 14, RGB(180, 180, 180), 13);
    }

    // HUD: Ammo
    if (g_reloading) {
        char rl[32]; sprintf_s(rl, skStr("RELOADING %.1fs"), g_reloadCd);
        DrawText_(dc, rl, 14, 38, RGB(255, 200, 50), 14, true);
    }
    else {
        int ammo = ACReadEnc(g_encAmmo);
        char am[32]; sprintf_s(am, skStr("AMMO %d/%d"), ammo, PLAYER_MAX_AMMO);
        DrawText_(dc, am, 14, 38,
            ammo > 5 ? RGB(180, 220, 180) : RGB(255, 80, 80), 14, true);
    }

    // HUD: Score / wave / kills
    char sc[64]; sprintf_s(sc, skStr("SCORE  %d"), ACReadEnc(g_encScore));
    DrawText_(dc, sc, SCREEN_W - 200, 14, RGB(255, 220, 50), 16, true);
    char wv[32]; sprintf_s(wv, skStr("WAVE   %d"), ACReadEnc(g_encWave));
    DrawText_(dc, wv, SCREEN_W - 200, 34, RGB(100, 200, 255), 15, true);
    char kl[32]; sprintf_s(kl, skStr("KILLS  %d"), ACReadEnc(g_encKills));
    DrawText_(dc, kl, SCREEN_W - 200, 52, RGB(180, 180, 180), 14);

    // HUD: Power weapon
    if (g_powerWeapon) {
        char wn0[16], wn1[16], wn2[16];
        strcpy_s(wn0, skStr("SHOTGUN")); strcpy_s(wn1, skStr("MINIGUN")); strcpy_s(wn2, skStr("ROCKET"));
        const char* wnames[] = { wn0, wn1, wn2 };
        COLORREF    wcols[] = { RGB(255, 180, 50), RGB(200, 100, 255), RGB(255, 80, 50) };
        char wbuf[64];
        sprintf_s(wbuf, "[%s] %.1fs", wnames[g_powerWeaponId], g_powerWeaponTimer);
        DrawText_(dc, wbuf, SCREEN_W / 2, 14, wcols[g_powerWeaponId], 18, true, true);
        DrawBar(dc, SCREEN_W / 2 - 100, 36, 200, 8,
            g_powerWeaponTimer / POWER_WEAPON_DURATION,
            wcols[g_powerWeaponId], RGB(40, 20, 20));
    }

    // HUD: FPS + AC status
    char fps[32]; sprintf_s(fps, skStr("FPS: %d"), g_fps);
    DrawText_(dc, fps, SCREEN_W - 80, SCREEN_H - 24, RGB(60, 80, 60), 12);
    DrawText_(dc, skStr("AC: ACTIVE"), 14, SCREEN_H - 24, RGB(50, 180, 50), 12);

    // Wave countdown
    if (!g_waveSpawning) {
        int ac = 0;
        for (auto& e : g_enemies) if (e.alive) ac++;
        if (ac == 0 && g_waveTimer < g_waveDelay) {
            char buf[64];
            sprintf_s(buf, skStr("NEXT WAVE IN %.1f..."), g_waveDelay - g_waveTimer);
            DrawText_(dc, buf, SCREEN_W / 2, 80, RGB(255, 220, 100), 22, true, true);
        }
    }

    // Pause overlay
    if (g_paused && !g_gameOver) {
        AlphaOverlay(dc, 180);
        int pw = 380, ph = 340;
        int px2 = SCREEN_W / 2 - pw / 2, py2 = SCREEN_H / 2 - ph / 2;
        DrawRect(dc, px2, py2, pw, ph, RGB(15, 20, 15));
        HPEN pp = CreatePen(PS_SOLID, 2, RGB(50, 180, 50));
        SelectObject(dc, pp); SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, px2, py2, px2 + pw, py2 + ph);
        DeleteObject(pp);

        DrawText_(dc, skStr("PAUSED"), SCREEN_W / 2, py2 + 24, RGB(100, 220, 100), 38, true, true);
        DrawText_(dc, skStr("TryBypassMe v3.0"), SCREEN_W / 2, py2 + 68, RGB(60, 120, 60), 14, false, true);

        HPEN dp = CreatePen(PS_SOLID, 1, RGB(40, 80, 40)); SelectObject(dc, dp);
        MoveToEx(dc, px2 + 20, py2 + 92, nullptr); LineTo(dc, px2 + pw - 20, py2 + 92);
        DeleteObject(dp);

        char sc3[64]; sprintf_s(sc3, skStr("Score   %d"), ACReadEnc(g_encScore));
        char wv3[32]; sprintf_s(wv3, skStr("Wave    %d"), ACReadEnc(g_encWave));
        char kl3[32]; sprintf_s(kl3, skStr("Kills   %d"), ACReadEnc(g_encKills));
        char hp3[32]; sprintf_s(hp3, skStr("Health  %d / %d"), ACReadEnc(g_encHp), PLAYER_MAX_HP);
        DrawText_(dc, sc3, SCREEN_W / 2, py2 + 108, RGB(255, 220, 50), 16, false, true);
        DrawText_(dc, wv3, SCREEN_W / 2, py2 + 132, RGB(100, 200, 255), 16, false, true);
        DrawText_(dc, kl3, SCREEN_W / 2, py2 + 156, RGB(180, 180, 180), 16, false, true);
        DrawText_(dc, hp3, SCREEN_W / 2, py2 + 180, RGB(80, 220, 80), 16, false, true);

        HPEN dp2 = CreatePen(PS_SOLID, 1, RGB(40, 80, 40)); SelectObject(dc, dp2);
        MoveToEx(dc, px2 + 20, py2 + 210, nullptr); LineTo(dc, px2 + pw - 20, py2 + 210);
        DeleteObject(dp2);

        DrawText_(dc, skStr("[ ESC ]  Resume"), SCREEN_W / 2, py2 + 224, RGB(120, 220, 120), 16, false, true);
        DrawText_(dc, skStr("[  R  ]  Restart"), SCREEN_W / 2, py2 + 248, RGB(120, 180, 220), 16, false, true);
        DrawText_(dc, skStr("[ALT+F4] Quit"), SCREEN_W / 2, py2 + 272, RGB(140, 80, 80), 16, false, true);
        DrawText_(dc, skStr("Created by DeadEye707 aka @ali123x on UC"),
            SCREEN_W / 2, py2 + ph - 42, RGB(80, 130, 80), 12, false, true);
        DrawText_(dc, skStr("AC: ACTIVE"),
            SCREEN_W / 2, py2 + ph - 24, RGB(50, 160, 50), 12, false, true);
    }

    // Game over screen
    if (g_gameOver) {
        AlphaOverlay(dc, 160);
        DrawText_(dc, skStr("GAME OVER"), SCREEN_W / 2, SCREEN_H / 2 - 120, RGB(255, 60, 60), 48, true, true);
        DrawText_(dc, skStr("TryBypassMe v3.0"), SCREEN_W / 2, SCREEN_H / 2 - 68, RGB(100, 180, 255), 18, false, true);
        char sc2[64]; sprintf_s(sc2, skStr("SCORE:  %d"), ACReadEnc(g_encScore));
        char hi[64];  sprintf_s(hi, skStr("BEST:   %d"), g_highScore);
        char wv2[32]; sprintf_s(wv2, skStr("WAVE:   %d"), ACReadEnc(g_encWave));
        char kl2[32]; sprintf_s(kl2, skStr("KILLS:  %d"), ACReadEnc(g_encKills));
        DrawText_(dc, sc2, SCREEN_W / 2, SCREEN_H / 2 - 30, RGB(255, 220, 50), 26, true, true);
        DrawText_(dc, hi, SCREEN_W / 2, SCREEN_H / 2 + 10, RGB(100, 200, 255), 22, false, true);
        DrawText_(dc, wv2, SCREEN_W / 2, SCREEN_H / 2 + 40, RGB(180, 180, 180), 20, false, true);
        DrawText_(dc, kl2, SCREEN_W / 2, SCREEN_H / 2 + 66, RGB(180, 180, 180), 20, false, true);
        DrawText_(dc, skStr("Press R to restart"), SCREEN_W / 2, SCREEN_H / 2 + 110, RGB(150, 150, 150), 18, false, true);
        DrawText_(dc, skStr("Press ESC to quit"), SCREEN_W / 2, SCREEN_H / 2 + 136, RGB(100, 100, 100), 15, false, true);

        // Show AC detection reason if flagged
        if (AcTokenIsDetected(g_acToken))
            DrawText_(dc, (std::string(skStr("CHEAT DETECTED: ")) + g_acReason).c_str(),
                SCREEN_W / 2, SCREEN_H - 50, RGB(255, 50, 50), 14, true, true);
    }
}

static void Present() {
    HDC hdc = GetDC(g_hwnd);
    BitBlt(hdc, 0, 0, SCREEN_W, SCREEN_H, g_memDC, 0, 0, SRCCOPY);
    ReleaseDC(g_hwnd, hdc);
}

// ============================================================
// RESTART
// ============================================================
static void RestartGame()
{
    g_playerPos = { SCREEN_W / 2.f, SCREEN_H / 2.f };
    g_shootCd = 0.f;
    g_reloadCd = 0.f;
    g_reloading = false;
    g_totalTime = 0.f;
    g_waveTimer = 0.f;
    g_waveSpawning = false;

    // Reset the game-over flag through the encrypted setter
    ACGameOverSet(false);

    ACWriteEnc(g_encHp, PLAYER_MAX_HP);
    ACWriteEnc(g_encAmmo, PLAYER_MAX_AMMO);
    ACWriteEnc(g_encScore, 0);
    ACWriteEnc(g_encKills, 0);
    ACWriteEnc(g_encWave, 1);

    ACSetPaused(false);
    ACSetPowerWeapon(false);
    g_powerWeaponTimer = 0.f;

    // Reset encrypted accounting counters
    g_totalDamageDealt_store(0);
    g_totalHealed_store(0);
    ACCounterSet(g_pShotsFiredCounter, 0);
    ACCounterSet(g_pAmmoConsumedCounter, 0);
    ACCounterSet(g_pAmmoRefilledCounter, 0);

    g_drops.clear();
    g_enemies.clear();
    g_bullets.clear();
    g_particles.clear();
    g_floatTexts.clear();
    g_particles.resize(512);
    g_floatTexts.resize(32);
    StartWave(1);
}

// ============================================================
// WINDOW PROCEDURE
// ============================================================
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_DESTROY: PostQuitMessage(0); return 0;
    case WM_KEYDOWN:
        g_keys[wp & 0xFF] = true;
        if (wp == VK_ESCAPE) {
            if (g_gameOver) PostQuitMessage(0);
            else ACSetPaused(!g_paused);
        }
        if (wp == 'R' && g_gameOver && !AcTokenIsDetected(g_acToken)) RestartGame();
        if (wp == 'R' && g_paused) { ACSetPaused(false); RestartGame(); }
        return 0;
    case WM_KEYUP:
        g_keys[wp & 0xFF] = false;
        return 0;
    case WM_LBUTTONDOWN: g_mouseLeft = true;  return 0;
    case WM_LBUTTONUP:   g_mouseLeft = false; return 0;
    case WM_MOUSEMOVE:
        g_mousePos.x = (short)LOWORD(lp);
        g_mousePos.y = (short)HIWORD(lp);
        return 0;
    case WM_SETCURSOR:
        SetCursor(LoadCursor(nullptr, IDC_CROSS));
        return TRUE;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

// ============================================================
// SPLASH SCREEN RENDERING
// ============================================================
static void RenderSplash(float elapsed, float maxWait, bool wdReady)
{
    HDC dc = g_memDC;
    // Dark background
    DrawRect(dc, 0, 0, SCREEN_W, SCREEN_H, RGB(10, 14, 10));

    // Animated background grid (scanning effect)
    int scanLine = ((int)(elapsed * 120.f)) % SCREEN_H;
    HPEN gp = CreatePen(PS_SOLID, 1, RGB(18, 28, 18));
    SelectObject(dc, gp);
    for (int x = 0; x < SCREEN_W; x += TILE_SIZE)
        MoveToEx(dc, x, 0, nullptr), LineTo(dc, x, SCREEN_H);
    for (int y = 0; y < SCREEN_H; y += TILE_SIZE)
        MoveToEx(dc, 0, y, nullptr), LineTo(dc, SCREEN_W, y);
    DeleteObject(gp);

    // Scan line effect
    HPEN sp = CreatePen(PS_SOLID, 2, RGB(30, 80, 30));
    SelectObject(dc, sp);
    MoveToEx(dc, 0, scanLine, nullptr);
    LineTo(dc, SCREEN_W, scanLine);
    DeleteObject(sp);

    // Faint glow behind scan line
    for (int dy = -8; dy <= 8; dy++) {
        int y = scanLine + dy;
        if (y < 0 || y >= SCREEN_H) continue;
        int alpha = 25 - abs(dy) * 3;
        if (alpha > 0) {
            HPEN glow = CreatePen(PS_SOLID, 1, RGB(0, alpha, 0));
            SelectObject(dc, glow);
            MoveToEx(dc, 0, y, nullptr);
            LineTo(dc, SCREEN_W, y);
            DeleteObject(glow);
        }
    }

    // Center panel
    int pw = 520, ph = 260;
    int px = SCREEN_W / 2 - pw / 2, py = SCREEN_H / 2 - ph / 2;

    // Panel background
    DrawRect(dc, px, py, pw, ph, RGB(12, 18, 12));

    // Panel border
    HPEN bp = CreatePen(PS_SOLID, 2, RGB(40, 160, 40));
    SelectObject(dc, bp);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, px, py, px + pw, py + ph);
    DeleteObject(bp);

    // Corner accents
    HPEN cp = CreatePen(PS_SOLID, 3, RGB(60, 200, 60));
    SelectObject(dc, cp);
    int cl = 20;
    // Top-left
    MoveToEx(dc, px, py + cl, nullptr); LineTo(dc, px, py); LineTo(dc, px + cl, py);
    // Top-right
    MoveToEx(dc, px + pw - cl, py, nullptr); LineTo(dc, px + pw, py); LineTo(dc, px + pw, py + cl);
    // Bottom-left
    MoveToEx(dc, px, py + ph - cl, nullptr); LineTo(dc, px, py + ph); LineTo(dc, px + cl, py + ph);
    // Bottom-right
    MoveToEx(dc, px + pw - cl, py + ph, nullptr); LineTo(dc, px + pw, py + ph); LineTo(dc, px + pw, py + ph - cl);
    DeleteObject(cp);

    // Shield icon (simple triangle)
    int sx = SCREEN_W / 2, sy = py + 50;
    HPEN shp = CreatePen(PS_SOLID, 3, RGB(50, 200, 50));
    SelectObject(dc, shp);
    POINT shield[4] = {
        { sx, sy - 22 },
        { sx + 20, sy + 2 },
        { sx, sy + 22 },
        { sx - 20, sy + 2 }
    };
    MoveToEx(dc, shield[0].x, shield[0].y, nullptr);
    for (int i = 1; i < 4; i++) LineTo(dc, shield[i].x, shield[i].y);
    LineTo(dc, shield[0].x, shield[0].y);
    DeleteObject(shp);

    // Checkmark inside shield
    HPEN ck = CreatePen(PS_SOLID, 2, RGB(100, 255, 100));
    SelectObject(dc, ck);
    MoveToEx(dc, sx - 8, sy, nullptr);
    LineTo(dc, sx - 2, sy + 8);
    LineTo(dc, sx + 10, sy - 6);
    DeleteObject(ck);

    // Title
    DrawText_(dc, skStr("TryBypassMe v3.0"), SCREEN_W / 2, py + 80,
        RGB(80, 200, 80), 28, true, true);

    // Subtitle
    DrawText_(dc, skStr("Anti-Cheat System"), SCREEN_W / 2, py + 108,
        RGB(60, 160, 60), 16, false, true);

    // Loading text with animated dots
    int dots = ((int)(elapsed * 2.5f)) % 4;
    char loadTxt[64];
    if (wdReady)
        sprintf_s(loadTxt, skStr("Verified. Starting game..."));
    else
        sprintf_s(loadTxt, skStr("Initializing%.*s"), dots, "...");
    DrawText_(dc, loadTxt, SCREEN_W / 2, py + 128,
        RGB(160, 220, 160), 18, false, true);

    // Status — real AC init steps
    const char* status = skStr("Setting up memory protection...");
    if (elapsed > 0.4f) status = skStr("Computing .text CRC baseline...");
    if (elapsed > 0.8f) status = skStr("Building DLL baseline snapshot...");
    if (elapsed > 1.2f) status = skStr("Spawning watchdog process...");
    if (elapsed > 1.6f) status = skStr("Establishing named pipe...");
    if (elapsed > 2.0f) status = skStr("Waiting for HMAC handshake...");
    if (wdReady)        status = skStr("Watchdog connected. All checks passed.");
    DrawText_(dc, status, SCREEN_W / 2, py + 150,
        RGB(80, 140, 80), 14, false, true);

    // Progress bar — fills over 3s (the minimum splash time)
    float frac = wdReady ? 1.0f : std::min(elapsed / 3.0f, 0.95f);
    int barW = 400, barH = 16;
    int barX = SCREEN_W / 2 - barW / 2, barY = py + 185;

    DrawRect(dc, barX, barY, barW, barH, RGB(20, 30, 20));
    int fillW = (int)(barW * frac);
    if (fillW > 0) {
        // Gradient-like fill (brighter in center)
        for (int x = 0; x < fillW; x++) {
            float t = (float)x / (float)barW;
            int g = 80 + (int)(140.f * t);
            int r = (int)(20.f * t);
            HPEN lp = CreatePen(PS_SOLID, 1, RGB(r, g, 20));
            SelectObject(dc, lp);
            MoveToEx(dc, barX + x, barY + 1, nullptr);
            LineTo(dc, barX + x, barY + barH - 1);
            DeleteObject(lp);
        }
    }

    // Bar border
    HPEN bb = CreatePen(PS_SOLID, 1, RGB(40, 100, 40));
    SelectObject(dc, bb);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, barX, barY, barX + barW, barY + barH);
    DeleteObject(bb);

    // Percentage
    char pctTxt[16];
    sprintf_s(pctTxt, "%d%%", (int)(frac * 100));
    DrawText_(dc, pctTxt, SCREEN_W / 2, barY + 22,
        RGB(60, 160, 60), 13, false, true);

    // Footer
    DrawText_(dc, skStr("Created by DeadEye707 aka @ali123x on UC"),
        SCREEN_W / 2, py + ph - 32, RGB(80, 140, 80), 14, false, true);
}

// ============================================================
//  ADMIN CHECK & PROMPT
// ============================================================
static bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

static int RenderAdminPrompt(float elapsed)
{
    HDC dc = g_memDC;
    DrawRect(dc, 0, 0, SCREEN_W, SCREEN_H, RGB(10, 14, 10));

    int scanLine = ((int)(elapsed * 120.f)) % SCREEN_H;
    HPEN gp = CreatePen(PS_SOLID, 1, RGB(18, 28, 18));
    SelectObject(dc, gp);
    for (int x = 0; x < SCREEN_W; x += TILE_SIZE) MoveToEx(dc, x, 0, nullptr), LineTo(dc, x, SCREEN_H);
    for (int y = 0; y < SCREEN_H; y += TILE_SIZE) MoveToEx(dc, 0, y, nullptr), LineTo(dc, SCREEN_W, y);
    DeleteObject(gp);

    HPEN sp = CreatePen(PS_SOLID, 2, RGB(80, 40, 40));
    SelectObject(dc, sp); MoveToEx(dc, 0, scanLine, nullptr); LineTo(dc, SCREEN_W, scanLine); DeleteObject(sp);

    int pw = 520, ph = 260;
    int px = SCREEN_W / 2 - pw / 2, py = SCREEN_H / 2 - ph / 2;
    DrawRect(dc, px, py, pw, ph, RGB(15, 12, 12));
    HPEN bp = CreatePen(PS_SOLID, 2, RGB(200, 40, 40));
    SelectObject(dc, bp); SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, px, py, px + pw, py + ph); DeleteObject(bp);

    DrawText_(dc, skStr("Administrator Setup Required"), SCREEN_W / 2, py + 80, RGB(220, 80, 80), 28, true, true);
    DrawText_(dc, skStr("TryBypassMe Anti-Cheat requires elevated permissions"), SCREEN_W / 2, py + 120, RGB(160, 160, 160), 16, false, true);
    DrawText_(dc, skStr("to monitor system memory correctly."), SCREEN_W / 2, py + 140, RGB(160, 160, 160), 16, false, true);

    int btnW = 180, btnH = 40;
    int btn1X = SCREEN_W / 2 - btnW - 10, btn1Y = py + 180;
    int btn2X = SCREEN_W / 2 + 10, btn2Y = py + 180;
    int mx = g_mousePos.x, my = g_mousePos.y;
    bool hover1 = (mx >= btn1X && mx <= btn1X + btnW && my >= btn1Y && my <= btn1Y + btnH);
    bool hover2 = (mx >= btn2X && mx <= btn2X + btnW && my >= btn2Y && my <= btn2Y + btnH);

    DrawRect(dc, btn1X, btn1Y, btnW, btnH, hover1 ? RGB(60, 140, 60) : RGB(40, 100, 40));
    HPEN p1 = CreatePen(PS_SOLID, 1, RGB(80, 180, 80)); SelectObject(dc, p1); SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, btn1X, btn1Y, btn1X + btnW, btn1Y + btnH); DeleteObject(p1);
    DrawText_(dc, skStr("Reopen as Admin"), btn1X + btnW / 2, btn1Y + 12, RGB(255, 255, 255), 16, true, true);

    DrawRect(dc, btn2X, btn2Y, btnW, btnH, hover2 ? RGB(140, 60, 60) : RGB(100, 40, 40));
    HPEN p2 = CreatePen(PS_SOLID, 1, RGB(180, 80, 80)); SelectObject(dc, p2); SelectObject(dc, GetStockObject(NULL_BRUSH)); Rectangle(dc, btn2X, btn2Y, btn2X + btnW, btn2Y + btnH); DeleteObject(p2);
    DrawText_(dc, skStr("Exit"), btn2X + btnW / 2, btn2Y + 12, RGB(255, 255, 255), 16, true, true);

    static bool wasDown = false;
    int action = 0;
    if (!g_mouseLeft && wasDown) {
        if (hover1) action = 1;
        if (hover2) action = 2;
    }
    wasDown = g_mouseLeft;
    return action;
}

// ============================================================
// ENTRY POINT
// ============================================================
int WINAPI WinMain(_In_ HINSTANCE hInst, _In_opt_ HINSTANCE, _In_ LPSTR, _In_ int)
{
    srand((unsigned)time(nullptr));

    // Keep class name in a local buffer so the skStr pointer doesn't dangle
    char className[32];
    strcpy_s(className, skStr("TryBypassMe"));

    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = className;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_CROSS);
    wc.hIcon = LoadIconA(hInst, MAKEINTRESOURCEA(101));
    wc.hIconSm = LoadIconA(hInst, MAKEINTRESOURCEA(101));
    RegisterClassExA(&wc);

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT  rc = { 0, 0, SCREEN_W, SCREEN_H };
    AdjustWindowRect(&rc, style, FALSE);

    g_hwnd = CreateWindowA(className, skStr("TryBypassMe v3.0 | Loading..."),
        style, CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, hInst, nullptr);
    ShowWindow(g_hwnd, SW_SHOW);

    g_hdc = GetDC(g_hwnd);
    g_memDC = CreateCompatibleDC(g_hdc);
    g_hbmp = CreateCompatibleBitmap(g_hdc, SCREEN_W, SCREEN_H);
    SelectObject(g_memDC, g_hbmp);

    // -------------------------------------------------------
    //  CHECK ADMINISTRATOR PRIVILEGES
    // -------------------------------------------------------
    if (!IsRunAsAdmin()) {
        LARGE_INTEGER pFreq, pStart, pNow;
        QueryPerformanceFrequency(&pFreq);
        QueryPerformanceCounter(&pStart);
        MSG pmsg{};
        while (true) {
            while (PeekMessageA(&pmsg, nullptr, 0, 0, PM_REMOVE)) {
                if (pmsg.message == WM_QUIT) return 0;
                TranslateMessage(&pmsg);
                DispatchMessageA(&pmsg);
            }
            QueryPerformanceCounter(&pNow);
            float elapsed = (float)(pNow.QuadPart - pStart.QuadPart) / pFreq.QuadPart;

            int action = RenderAdminPrompt(elapsed);
            Present();
            Sleep(16);

            if (action == 1) { // Reopen as Admin
                char path[MAX_PATH];
                GetModuleFileNameA(NULL, path, MAX_PATH);
                ShellExecuteA(NULL, skStr("runas"), path, NULL, NULL, SW_SHOWNORMAL);
                return 0;
            }
            if (action == 2) { // Exit
                return 0;
            }
        }
    }

    // -------------------------------------------------------
    //  INIT ANTI-CHEAT (spawns watchdog + threads)
    // -------------------------------------------------------
    ACInit();

    // -------------------------------------------------------
    //  SPLASH SCREEN: always shown for at least 3 seconds.
    //  Shows animated loading screen while WatchdogMain.exe
    //  connects and completes the HMAC handshake.
    //  If watchdog connects fast, splash still displays the
    //  full init sequence for a polished experience.
    // -------------------------------------------------------
    {
        LARGE_INTEGER splashFreq, splashStart, splashNow;
        QueryPerformanceFrequency(&splashFreq);
        QueryPerformanceCounter(&splashStart);

        float maxWaitSec = 12.0f; // matches WD_CONNECT_DEADLINE_MS
        float minSplashSec = 3.0f; // minimum splash display time

        MSG smsg{};
        bool wdReady = false;
        while (true) {
            // Pump messages so window stays responsive
            while (PeekMessageA(&smsg, nullptr, 0, 0, PM_REMOVE)) {
                if (smsg.message == WM_QUIT) return 0;
                TranslateMessage(&smsg);
                DispatchMessageA(&smsg);
            }

            QueryPerformanceCounter(&splashNow);
            float elapsed = (float)(splashNow.QuadPart - splashStart.QuadPart)
                / splashFreq.QuadPart;

            // Check watchdog status
            wdReady = ACIsWatchdogReady();

            // ACTick checks the deadline and kills if exceeded
            ACTick();

            RenderSplash(elapsed, maxWaitSec, wdReady);
            Present();
            Sleep(16); // ~60fps

            // Exit splash when BOTH: watchdog is ready AND minimum time elapsed
            if (wdReady && elapsed >= minSplashSec) break;
        }

        // Update window title
        SetWindowTextA(g_hwnd, skStr("TryBypassMe v3.0 | WASD + Mouse"));
    }

    // -------------------------------------------------------
    //  GAME INIT
    // -------------------------------------------------------
    g_particles.resize(512);
    g_floatTexts.resize(32);

    StartWave(1);

    LARGE_INTEGER freq, prev, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&prev);
    int   frameCount = 0;
    float fpsTimer = 0.f;

    MSG msg{};
    while (true) {
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) goto done;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        QueryPerformanceCounter(&now);
        float dt = (float)(now.QuadPart - prev.QuadPart) / freq.QuadPart;
        prev = now;
        dt = std::min(dt, .05f);

        fpsTimer += dt;
        frameCount++;
        if (fpsTimer >= 1.f) { g_fps = frameCount; frameCount = 0; fpsTimer = 0.f; }

        Update(dt);
        RenderGame();
        Present();
        Sleep(1);
    }
done:
    return 0;
}