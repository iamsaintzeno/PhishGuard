const scanButton = document.getElementById("scanButton");
const urlInput = document.getElementById("urlInput");

const loading = document.getElementById("loading");
const result = document.getElementById("result");

const verdict = document.getElementById("verdict");
const score = document.getElementById("score");

const scoreCircle = document.getElementById("scoreCircle");
const riskProgress = document.getElementById("riskProgress");

const reasonsContainer = document.getElementById("reasons");
const scannedUrl = document.getElementById("scannedUrl");


console.log("PhishGuard JavaScript loaded successfully!");


scanButton.addEventListener("click", scanURL);


function scanURL() {

    console.log("Scan button clicked!");

    const url = urlInput.value.trim();


    if (url === "") {

        alert("Please enter a URL.");

        return;
    }


    loading.classList.remove("hidden");

    result.classList.add("hidden");


    setTimeout(function () {

        let riskScore = 0;

        let reasons = [];

        const lowerURL = url.toLowerCase();


        // 1. HTTPS CHECK

        if (!lowerURL.startsWith("https://")) {

            riskScore += 20;

            reasons.push(
                "URL does not use HTTPS."
            );

        }


        // 2. IP ADDRESS CHECK

        const ipPattern =
            /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/;


        if (ipPattern.test(url)) {

            riskScore += 25;

            reasons.push(
                "URL uses an IP address instead of a domain name."
            );

        }


        // 3. LONG URL CHECK

        if (url.length > 100) {

            riskScore += 15;

            reasons.push(
                "URL is unusually long."
            );

        }


        // 4. SUSPICIOUS KEYWORDS

        const keywords = [
            "login",
            "verify",
            "bank",
            "password",
            "signin",
            "account",
            "update",
            "confirm"
        ];


        let foundKeywords = [];


        keywords.forEach(function (keyword) {

            if (lowerURL.includes(keyword)) {

                foundKeywords.push(keyword);

            }

        });


        if (foundKeywords.length > 0) {

            riskScore += foundKeywords.length * 8;

            reasons.push(
                "Suspicious keyword(s): " +
                foundKeywords.join(", ")
            );

        }


        // 5. @ SYMBOL CHECK

        if (url.includes("@")) {

            riskScore += 20;

            reasons.push(
                "URL contains an @ symbol."
            );

        }


        // 6. SUBDOMAIN CHECK

        try {

            const fullURL =
                url.startsWith("http")
                    ? url
                    : "https://" + url;


            const hostname =
                new URL(fullURL).hostname;


            const parts =
                hostname.split(".");


            if (parts.length >= 4) {

                riskScore += 15;

                reasons.push(
                    "URL contains too many subdomains."
                );

            }

        }

        catch (error) {

            riskScore += 20;

            reasons.push(
                "URL format appears invalid."
            );

        }


        // Maximum score = 100

        if (riskScore > 100) {

            riskScore = 100;

        }


        // VERDICT

        let finalVerdict;


        if (riskScore >= 60) {

            finalVerdict = "Dangerous";

        }

        else if (riskScore >= 30) {

            finalVerdict = "Suspicious";

        }

        else {

            finalVerdict = "Safe";

        }


        // If no problems found

        if (reasons.length === 0) {

            reasons.push(
                "No obvious phishing indicators were detected."
            );

        }


        // DISPLAY SCORE

        score.textContent = riskScore;

        verdict.textContent = finalVerdict;

        scannedUrl.textContent = url;


        // RISK BAR

        riskProgress.style.width =
            riskScore + "%";


        // RESET COLORS

        verdict.style.color = "";

        scoreCircle.style.background = "";

        scoreCircle.style.color = "";

        riskProgress.style.background = "";


        // SAFE

        if (finalVerdict === "Safe") {

            verdict.style.color = "#16a34a";

            scoreCircle.style.background = "#dcfce7";

            scoreCircle.style.color = "#16a34a";

            riskProgress.style.background = "#22c55e";

        }


        // SUSPICIOUS

        else if (finalVerdict === "Suspicious") {

            verdict.style.color = "#d97706";

            scoreCircle.style.background = "#fef3c7";

            scoreCircle.style.color = "#d97706";

            riskProgress.style.background = "#f59e0b";

        }


        // DANGEROUS

        else {

            verdict.style.color = "#dc2626";

            scoreCircle.style.background = "#fee2e2";

            scoreCircle.style.color = "#dc2626";

            riskProgress.style.background = "#ef4444";

        }


        // DISPLAY REASONS

        reasonsContainer.innerHTML = "";


        reasons.forEach(function (reason) {

            const div =
                document.createElement("div");


            div.className = "reason";


            const icon =
                document.createElement("span");

            icon.className = "reason-icon";

            icon.textContent = "⚠";


            const text =
                document.createElement("span");

            text.textContent = reason;


            div.appendChild(icon);

            div.appendChild(text);


            reasonsContainer.appendChild(div);

        });


        // SAVE HISTORY

        let history =
            JSON.parse(
                localStorage.getItem("scanHistory")
            ) || [];


        history.unshift({

            url: url,

            score: riskScore,

            verdict: finalVerdict,

            time: new Date().toLocaleString()

        });


        // Keep only last 20 scans

        history = history.slice(0, 20);


        localStorage.setItem(
            "scanHistory",
            JSON.stringify(history)
        );


        // SHOW RESULT

        loading.classList.add("hidden");

        result.classList.remove("hidden");


        console.log("Scan completed!");

    }, 800);

}