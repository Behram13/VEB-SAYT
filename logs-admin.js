let allLogs = [];

const tableBody = document.getElementById("logsTableBody");
const logCount = document.getElementById("logCount");
const failedLoginCount = document.getElementById("failedLoginCount");
const blockedCount = document.getElementById("blockedCount");
const finFilter = document.getElementById("finFilter");
const eventFilter = document.getElementById("eventFilter");

async function loadLogs() {
    try {
        const response = await fetch("/security-logs");
        const data = await response.json();

        if (!response.ok) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="9">Logları yükləmək mümkün olmadı.</td>
                </tr>
            `;
            logCount.innerText = "0";
            failedLoginCount.innerText = "0";
            blockedCount.innerText = "0";
            return;
        }

        allLogs = data;

        updateStatistics();
        renderLogs(allLogs);

    } catch (error) {
        console.error("Security logs xətası:", error);

        tableBody.innerHTML = `
            <tr>
                <td colspan="9">Serverlə əlaqə yaratmaq mümkün olmadı.</td>
            </tr>
        `;

        logCount.innerText = "0";
        failedLoginCount.innerText = "0";
        blockedCount.innerText = "0";
    }
}

function updateStatistics() {
    logCount.innerText = allLogs.length;

    const failedLogins = allLogs.filter(function (log) {
        return log.event_type === "LOGIN_FAILED";
    });

    const blockedAccounts = allLogs.filter(function (log) {
        return log.event_type === "ACCOUNT_LOCKED";
    });

    failedLoginCount.innerText = failedLogins.length;
    blockedCount.innerText = blockedAccounts.length;
}

function renderLogs(logs) {
    tableBody.innerHTML = "";

    if (logs.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="9">Uyğun log tapılmadı.</td>
            </tr>
        `;
        return;
    }

    logs.forEach(function (log) {
        const row = document.createElement("tr");

        const eventClass = getEventClass(log.event_type);

        const resultClass =
            log.result === "SUCCESS"
                ? "result-success"
                : "result-failed";

        let lockedUntil = "-";

        if (log.locked_until) {
            lockedUntil = new Date(
                log.locked_until
            ).toLocaleString("az-AZ");
        }

        let createdAt = "-";

        if (log.created_at) {
            createdAt = new Date(
                log.created_at
            ).toLocaleString("az-AZ");
        }

        row.innerHTML = `
            <td>${log.id}</td>
            <td>${escapeHtml(log.fin || "-")}</td>
            <td class="${eventClass}">
                ${escapeHtml(translateEvent(log.event_type))}
            </td>
            <td class="${resultClass}">
                ${escapeHtml(translateResult(log.result))}
            </td>
            <td class="details-cell">
                ${escapeHtml(log.details || "-")}
            </td>
            <td>${log.failed_attempts ?? 0}</td>
            <td>${lockedUntil}</td>
            <td>${escapeHtml(log.ip_address || "-")}</td>
            <td>${createdAt}</td>
        `;

        tableBody.appendChild(row);
    });
}

function filterLogs() {
    const finValue =
        finFilter.value
            .trim()
            .toUpperCase();

    const eventValue =
        eventFilter.value;

    const filtered = allLogs.filter(function (log) {
        const logFin =
            (log.fin || "")
                .toUpperCase();

        const matchesFin =
            !finValue ||
            logFin.includes(finValue);

        const matchesEvent =
            !eventValue ||
            log.event_type === eventValue;

        return matchesFin && matchesEvent;
    });

    renderLogs(filtered);
}

finFilter.addEventListener("input", filterLogs);
eventFilter.addEventListener("change", filterLogs);

function getEventClass(eventType) {
    switch (eventType) {
        case "REGISTER_SUCCESS":
        case "REGISTER_FAILED":
            return "event-register";

        case "LOGIN_SUCCESS":
            return "event-login-success";

        case "LOGIN_FAILED":
            return "event-login-failed";

        case "ACCOUNT_LOCKED":
            return "event-locked";

        case "LOGIN_BLOCKED":
            return "event-blocked";

        case "LOGOUT_SUCCESS":
            return "event-logout";

        case "PASSWORD_CHANGED":
        case "PASSWORD_CHANGE_FAILED":
            return "event-password";

        case "APPOINTMENT_CREATED":
            return "event-appointment";

        default:
            return "";
    }
}

function translateEvent(eventType) {
    switch (eventType) {
        case "REGISTER_SUCCESS":
            return "Qeydiyyat uğurlu";

        case "REGISTER_FAILED":
            return "Qeydiyyat uğursuz";

        case "LOGIN_SUCCESS":
            return "Giriş uğurlu";

        case "LOGIN_FAILED":
            return "Giriş uğursuz";

        case "ACCOUNT_LOCKED":
            return "Hesab bloklandı";

        case "LOGIN_BLOCKED":
            return "Bloklu hesaba giriş";

        case "LOGOUT_SUCCESS":
            return "Hesabdan çıxış";

        case "PASSWORD_CHANGED":
            return "Parol dəyişdirildi";

        case "PASSWORD_CHANGE_FAILED":
            return "Parol dəyişmə uğursuz";

        case "APPOINTMENT_CREATED":
            return "Növbə yaradıldı";

        default:
            return eventType;
    }
}

function translateResult(result) {
    if (result === "SUCCESS") {
        return "Uğurlu";
    }

    if (result === "FAILED") {
        return "Uğursuz";
    }

    return result || "-";
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value ?? "";
    return div.innerHTML;
}

loadLogs();