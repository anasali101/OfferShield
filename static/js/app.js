/* ==========================================================================
   OfferShield — client-side behaviour
   No inline scripts (strict CSP). All DOM updates happen here.
   ========================================================================== */
(function () {
  "use strict";

  var EXAMPLES = {
    scam:
      "Congratulations! You have been SELECTED for the post of Data Entry Executive at Infosys Ltd. " +
      "Salary Rs 45,000 per month, work from home. This is a limited offer, reply within 2 hours or the " +
      "seat will be cancelled. To confirm your joining you must pay a refundable registration fee of " +
      "Rs 2,000 and a security deposit of Rs 5,000. Pay to UPI id hrpayments@okaxis or transfer to " +
      "account 123456789012. Send your Aadhaar card, PAN card and bank details for onboarding. " +
      "Contact HR Manager on WhatsApp +91 9000000000 or email infosys.hr.recruit@gmail.com. " +
      "Offer letter will be issued after payment. Hurry, only 3 seats left!",
    legit:
      "Dear Candidate, thank you for your application to the Software Engineer role at Acme Technologies. " +
      "We would like to invite you for a technical interview on 20 November at 3:00 PM IST via video call. " +
      "The interview will cover data structures, system design and a discussion with the hiring manager. " +
      "There is no fee at any stage of our recruitment process and we will never ask for payment or your " +
      "bank details. Please confirm your availability by replying to this email from our careers portal at " +
      "https://careers.acme-tech.example. Regards, Talent Acquisition Team, Acme Technologies Pvt Ltd."
  };

  var POLL_INTERVAL = 700;
  var MAX_POLL_ERRORS = 6;

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }
  function $$(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function show(el) {
    if (el) el.hidden = false;
  }
  function hide(el) {
    if (el) el.hidden = true;
  }

  /* ------------------------------- mobile nav ------------------------------ */
  function initNav() {
    var toggle = $(".nav-toggle");
    var links = $("#primary-nav");
    if (!toggle || !links) return;
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    links.addEventListener("click", function (event) {
      if (event.target.closest("a")) {
        links.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ---------------------------------- tabs --------------------------------- */
  function initTabs() {
    var tabs = $$(".tab[data-tab]");
    if (!tabs.length) return;
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        var name = tab.getAttribute("data-tab");
        tabs.forEach(function (t) {
          var active = t === tab;
          t.classList.toggle("is-active", active);
          t.setAttribute("aria-selected", active ? "true" : "false");
          var panel = $("#panel-" + t.getAttribute("data-tab"));
          if (panel) panel.hidden = !active;
        });
        var current = $("#panel-" + name);
        var field = current ? current.querySelector("textarea, input[type=url]") : null;
        if (field) field.focus();
      });
    });
  }

  /* ----------------------------- text analysis ----------------------------- */
  function initCharCount() {
    var textarea = $("#scan-text");
    var counter = $("#char-count");
    if (!textarea || !counter) return;
    var update = function () {
      counter.textContent = textarea.value.length.toLocaleString() + " characters";
    };
    textarea.addEventListener("input", update);
    update();
  }

  function initExamples() {
    var textarea = $("#scan-text");
    if (!textarea) return;
    $$("[data-example]").forEach(function (button) {
      button.addEventListener("click", function () {
        var key = button.getAttribute("data-example");
        if (!EXAMPLES[key]) return;
        textarea.value = EXAMPLES[key];
        textarea.dispatchEvent(new Event("input"));
        textarea.focus();
      });
    });
  }

  /* ------------------------------ pdf dropzone ----------------------------- */
  function initDropzone() {
    var input = $("#pdf-file");
    var zone = $("#dropzone");
    var chip = $("#file-chip");
    if (!input || !zone) return;

    var setFile = function (file) {
      if (!file) return;
      if (!/\.pdf$/i.test(file.name)) {
        showError("#error-pdf", "Please choose a PDF file (.pdf).");
        input.value = "";
        if (chip) hide(chip);
        return;
      }
      hideError("#error-pdf");
      if (chip) {
        chip.textContent = file.name + " · " + Math.ceil(file.size / 1024) + " KB";
        show(chip);
      }
    };

    input.addEventListener("change", function () {
      if (input.files && input.files[0]) setFile(input.files[0]);
    });

    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        zone.classList.add("is-drag");
      });
    });
    ["dragleave", "drop"].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        zone.classList.remove("is-drag");
      });
    });
    zone.addEventListener("drop", function (event) {
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files[0]) {
        input.files = files;
        setFile(files[0]);
      }
    });
  }

  /* ------------------------------- error utils ----------------------------- */
  function showError(selector, message) {
    var el = $(selector);
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
  }
  function hideError(selector) {
    var el = $(selector);
    if (el) {
      el.hidden = true;
      el.textContent = "";
    }
  }

  function setLoading(button, loading) {
    if (!button) return;
    button.disabled = loading;
    button.classList.toggle("is-loading", loading);
  }

  /* ------------------------------- submission ------------------------------ */
  function submitForm(form, options) {
    var button = form.querySelector("[data-submit]");
    var errorSelector = options.errorSelector;
    hideError(errorSelector);
    setLoading(button, true);

    var request;
    if (options.buildBody) {
      request = fetch("/api/analyze", {
        method: "POST",
        headers: { Accept: "application/json" },
        body: options.buildBody(form)
      });
    } else {
      request = fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(options.buildJson(form))
      });
    }

    request
      .then(function (response) {
        return response.json().then(function (data) {
          return { ok: response.ok, status: response.status, data: data };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          throw new Error((result.data && result.data.error) || "The scan could not be started.");
        }
        startProgress(result.data);
      })
      .catch(function (error) {
        setLoading(button, false);
        showError(errorSelector, error.message || "Something went wrong. Please try again.");
      });
  }

  function buildTextBody(form) {
    return {
      type: "text",
      text: form.querySelector("#scan-text").value,
      consent: form.querySelector("#consent-text").checked
    };
  }

  function buildUrlBody(form) {
    return {
      type: "url",
      url: form.querySelector("#scan-url").value,
      consent: form.querySelector("#consent-url").checked
    };
  }

  function buildPdfBody(form) {
    var data = new FormData();
    var file = form.querySelector("#pdf-file");
    if (!file.files || !file.files[0]) return null;
    data.append("file", file.files[0]);
    data.append("consent", form.querySelector("#consent-pdf").checked ? "true" : "false");
    return data;
  }

  function initForms() {
    var textForm = $("#form-text");
    if (textForm) {
      textForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var value = textForm.querySelector("#scan-text").value;
        if (value.trim().length < 10) {
          showError("#error-text", "Please provide at least 10 characters of offer text.");
          return;
        }
        submitForm(textForm, { buildJson: buildTextBody, errorSelector: "#error-text" });
      });
    }

    var urlForm = $("#form-url");
    if (urlForm) {
      urlForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var value = urlForm.querySelector("#scan-url").value.trim();
        if (!/^https?:\/\//i.test(value)) {
          showError("#error-url", "Please enter a full URL starting with http:// or https://");
          return;
        }
        submitForm(urlForm, { buildJson: buildUrlBody, errorSelector: "#error-url" });
      });
    }

    var pdfForm = $("#form-pdf");
    if (pdfForm) {
      pdfForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var file = pdfForm.querySelector("#pdf-file");
        if (!file.files || !file.files[0]) {
          showError("#error-pdf", "Please choose a PDF offer letter to analyse.");
          return;
        }
        submitForm(pdfForm, { buildBody: buildPdfBody, errorSelector: "#error-pdf" });
      });
    }
  }

  /* ------------------------------- progress -------------------------------- */
  var pollState = { timer: null, errors: 0, jobId: null };

  function startProgress(payload) {
    var panel = $("#analysis-panel");
    if (!panel || !payload || !payload.job_id) return;
    hideError("#analysis-error");
    hide($("#analysis-done"));
    hide($("#analysis-actions"));
    show(panel);

    $("#analysis-kind").textContent = payload.kind || "scan";
    $("#analysis-title").textContent = "Running checks…";

    var kindBadge = $("#analysis-kind");
    if (kindBadge && payload.filename) kindBadge.textContent = "PDF · " + payload.filename;

    renderSteps(payload.steps || []);
    updateProgress(payload.steps || []);
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });

    pollState.jobId = payload.job_id;
    pollState.errors = 0;
    schedulePoll(120);
  }

  function schedulePoll(delay) {
    clearTimeout(pollState.timer);
    pollState.timer = setTimeout(pollJob, delay);
  }

  function pollJob() {
    if (!pollState.jobId) return;
    fetch("/api/job/" + pollState.jobId, { headers: { Accept: "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error("lost");
        return response.json();
      })
      .then(function (job) {
        pollState.errors = 0;
        renderSteps(job.steps || []);
        updateProgress(job.steps || []);

        if (job.status === "done") {
          finishProgress(job);
          return;
        }
        if (job.status === "error") {
          failProgress(job.error || "The scan failed. Please try again.");
          return;
        }
        schedulePoll(POLL_INTERVAL);
      })
      .catch(function () {
        pollState.errors += 1;
        if (pollState.errors >= MAX_POLL_ERRORS) {
          failProgress("Lost contact with the server. Please start a new scan.");
          return;
        }
        schedulePoll(POLL_INTERVAL * 2);
      });
  }

  function renderSteps(steps) {
    var list = $("#step-list");
    if (!list) return;
    list.innerHTML = "";
    steps.forEach(function (step) {
      var li = document.createElement("li");
      li.className = "analysis-step is-" + (step.status || "pending");
      var dot = document.createElement("span");
      dot.className = "mini-dot";
      dot.setAttribute("aria-hidden", "true");
      var body = document.createElement("span");
      var label = document.createElement("strong");
      label.textContent = step.label;
      body.appendChild(label);
      if (step.detail) {
        var detail = document.createElement("small");
        detail.textContent = step.detail;
        body.appendChild(detail);
      }
      li.appendChild(dot);
      li.appendChild(body);
      list.appendChild(li);
    });
  }

  function updateProgress(steps) {
    var total = steps.length || 1;
    var done = steps.filter(function (s) {
      return s.status === "done" || s.status === "skipped" || s.status === "failed";
    }).length;
    var running = steps.filter(function (s) {
      return s.status === "running";
    })[0];
    var percent = Math.round((done / total) * 100);

    var fill = $("#progress-fill");
    var track = $("#progress-track");
    var count = $("#progress-count");
    var label = $("#progress-label");
    if (fill) fill.style.width = percent + "%";
    if (track) track.setAttribute("aria-valuenow", String(percent));
    if (count) count.textContent = done + " / " + total;
    if (label) {
      label.textContent = running
        ? running.label + "…"
        : done === total
        ? "Finalising report…"
        : "Preparing analysis…";
    }
  }

  function finishProgress(job) {
    var steps = job.steps || [];
    renderSteps(steps);
    updateProgress(steps);
    var fill = $("#progress-fill");
    if (fill) fill.style.width = "100%";
    $("#analysis-title").textContent = "Report ready";
    show($("#analysis-done"));
    if (job.result_url) {
      setTimeout(function () {
        window.location.assign(job.result_url);
      }, 550);
    } else {
      show($("#analysis-actions"));
    }
  }

  function failProgress(message) {
    clearTimeout(pollState.timer);
    pollState.jobId = null;
    $("#analysis-title").textContent = "Scan stopped";
    showError("#analysis-error", message);
    show($("#analysis-actions"));
  }

  function initReset() {
    var button = $("#reset-analysis");
    if (!button) return;
    button.addEventListener("click", function () {
      clearTimeout(pollState.timer);
      pollState.jobId = null;
      hide($("#analysis-panel"));
      $$("form.scan-form").forEach(function (form) {
        form.reset();
        var submit = form.querySelector("[data-submit]");
        setLoading(submit, false);
      });
      $$(".form-error").forEach(function (el) {
        hide(el);
      });
      var chip = $("#file-chip");
      if (chip) hide(chip);
      var counter = $("#char-count");
      if (counter) counter.textContent = "0 characters";
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  /* -------------------------------- results -------------------------------- */
  function initMeters() {
    var fills = $$("[data-width]");
    if (!fills.length) return;
    var apply = function () {
      fills.forEach(function (fill) {
        var width = parseFloat(fill.getAttribute("data-width")) || 0;
        fill.style.width = Math.max(0, Math.min(100, width)) + "%";
      });
    };
    if ("requestAnimationFrame" in window) {
      requestAnimationFrame(function () {
        requestAnimationFrame(apply);
      });
    } else {
      apply();
    }
  }

  function initFilters() {
    var chips = $$("[data-filter]");
    var cards = $$(".finding-card[data-group]");
    if (!chips.length || !cards.length) return;
    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        var filter = chip.getAttribute("data-filter");
        chips.forEach(function (c) {
          c.classList.toggle("is-active", c === chip);
        });
        cards.forEach(function (card) {
          var group = card.getAttribute("data-group");
          card.hidden = !(filter === "all" || group === filter);
        });
      });
    });
  }

  function initCopyLink() {
    $$("[data-copy-link]").forEach(function (button) {
      button.addEventListener("click", function () {
        var value = button.getAttribute("data-copy-link");
        var original = button.textContent;
        var done = function () {
          button.textContent = "Link copied";
          setTimeout(function () {
            button.textContent = original;
          }, 1800);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(value).then(done, function () {
            fallbackCopy(value, done);
          });
        } else {
          fallbackCopy(value, done);
        }
      });
    });
  }

  function fallbackCopy(value, done) {
    var area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "readonly");
    area.style.position = "fixed";
    area.style.top = "-1000px";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
      done();
    } catch (error) {
      /* clipboard unavailable */
    }
    document.body.removeChild(area);
  }

  /* ---------------------------------- init --------------------------------- */
  function init() {
    initNav();
    initTabs();
    initCharCount();
    initExamples();
    initDropzone();
    initForms();
    initReset();
    initMeters();
    initFilters();
    initCopyLink();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
