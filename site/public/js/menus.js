// Header dropdowns: the nav items that carry data-menu (Docs, Rules) open a panel of links
// (src/components/HeaderMenus.astro), at every width.
//  - Mouse: hovering an item opens its panel (after a short pause, so a pointer passing over
//    the bar does not flash it), moving on to the other item switches panels, and leaving both
//    the item and the panel closes it after another short pause. A click follows the link.
//  - Touch and pen: a tap follows the item's link. Holding the item a moment (HOLD, while its
//    chevron turns over) opens its panel instead, with neither the browser's long-press menu
//    nor the link followed when the finger lifts; a press that moves is a scroll, and is let
//    go. A tap anywhere else closes the panel.
//  - Keyboard: ArrowDown on an item opens its panel and focuses the first link; Escape closes
//    it and returns to the item. Enter follows the item's link.
// Both panels sit on one surface (.menus) that pours out of its item and drains back into it.
// Between items it springs to the next panel's size while the panels slide across the way the
// pointer went. A pill (.nav-glide) glides behind the hovered, held or open item. See .menus
// in global.css.
(function () {
  const OPEN_DELAY = 80, SWITCH_DELAY = 50, CLOSE_DELAY = 140, LEAVE_DELAY = 90, SHIFT = 56;
  const HOLD = 350; // as long as the chevron takes to turn over (nav.main a.holding .chev)
  const run = () => {
    const header = document.querySelector("header.site");
    const nav = header && header.querySelector("nav.main");
    const shell = header && header.querySelector("[data-menus]");
    if (!nav || !shell) return;
    const links = [...nav.querySelectorAll("a")];
    const triggers = links.filter((a) => a.dataset.menu);
    const panels = new Map([...shell.querySelectorAll("[data-menu-panel]")].map((p) => [p.dataset.menuPanel, p]));
    if (!triggers.length) return;
    const trigger = (name) => triggers.find((t) => t.dataset.menu === name);
    let current = null, hovered = null;
    let hold = null, held = false; // a finger held on an item, and whether a hold opened a panel
    let openTimer = 0, closeTimer = 0, leaveTimer = 0;

    // make a change at once, without its transitions
    const snap = (el, change) => { el.classList.add("snap"); change(); void el.offsetWidth; el.classList.remove("snap"); };
    const showing = (el) => parseFloat(getComputedStyle(el).opacity) > 0.01;
    const set = (el, prop, px) => el.style.setProperty(prop, `${px.toFixed(1)}px`);

    // the pill behind the nav items
    const pill = document.createElement("span");
    pill.className = "nav-glide";
    pill.setAttribute("aria-hidden", "true");
    nav.append(pill);
    nav.classList.add("glides");
    let pillOn = null;
    const glide = (link, instant) => {
      pillOn = link;
      if (!link) return pill.classList.remove("on");
      const a = link.getBoundingClientRect(), n = nav.getBoundingClientRect();
      const place = () => {
        set(pill, "--glide-x", a.left - n.left);
        set(pill, "--glide-y", a.top - n.top);
        set(pill, "--glide-w", a.width);
        set(pill, "--glide-h", a.height);
      };
      // from hidden it appears where it is needed, rather than sliding over from where it was
      if (instant || !showing(pill)) snap(pill, place);
      else place();
      pill.classList.add("on");
    };

    // size the surface to a panel; note the pill it pours from (the item's width, along the
    // surface's top; the surface is centred under the header at every width); and bridge the
    // gap up to the nav items
    const fit = (name) => {
      const panel = panels.get(name), item = trigger(name).getBoundingClientRect(), box = header.getBoundingClientRect();
      const edge = shell.offsetHeight - shell.clientHeight;
      const w = panel.offsetWidth + edge, h = panel.offsetHeight + edge;
      const left = box.left + box.width / 2 - w / 2, top = box.top + shell.offsetTop;
      const lowest = Math.max(...links.map((a) => a.getBoundingClientRect().bottom));
      set(shell, "--menu-w", w);
      set(shell, "--menu-h", h);
      set(shell, "--menu-x", item.left + item.width / 2 - (left + w / 2));
      set(shell, "--menu-l0", Math.max(0, item.left - left));
      set(shell, "--menu-r0", Math.max(0, left + w - item.right));
      set(shell, "--menu-b0", Math.max(0, h - item.height));
      set(shell, "--menu-gap", Math.max(0, top + edge / 2 - lowest));
    };

    // each heading and link rises into focus as the pour reaches it: once the bar has spread
    // out to it and the flow has come down to it (pace 1), or at once (pace 0)
    const wet = (name, pace) => {
      const panel = panels.get(name), item = trigger(name).getBoundingClientRect(), box = header.getBoundingClientRect();
      const x = item.left + item.width / 2 - (box.left + box.width / 2 - panel.offsetWidth / 2);
      for (const el of panel.querySelectorAll(".menu-head, .menu-col li, .menu-grid li, .menu-foot")) {
        const dx = Math.max(0, Math.abs(el.offsetLeft + el.offsetWidth / 2 - x) - el.offsetWidth / 2);
        const delay = pace * Math.max(40 + 0.28 * dx, 80 + 0.72 * el.offsetTop);
        el.style.setProperty("--menu-delay", `${Math.round(delay)}ms`);
      }
    };

    const show = (name) => {
      clearTimeout(openTimer);
      clearTimeout(closeTimer);
      if (current === name) return;
      const panel = panels.get(name), item = trigger(name);
      // the panel on the surface now, if the surface is still on screen (it may be draining)
      const from = showing(shell) ? [...panels.keys()].find((n) => panels.get(n).classList.contains("on")) : null;
      current = name;
      for (const t of triggers) {
        t.classList.toggle("menu-open", t === item);
        t.setAttribute("aria-expanded", String(t === item));
      }
      if (!from) {
        // from closed: the surface takes the panel's size, and the item's pill as its clip
        snap(shell, () => {
          for (const [n, p] of panels) {
            p.classList.toggle("on", n === name);
            p.style.setProperty("--menu-shift", "0px");
          }
          fit(name);
        });
        for (const n of panels.keys()) wet(n, n === name ? 1 : 0);
      } else if (from !== name) {
        // on to the other item: the surface springs to the new size, and the panels slide
        // across the way the pointer went (a panel still fading out turns back from where it is)
        const way = triggers.indexOf(item) > triggers.indexOf(trigger(from)) ? 1 : -1;
        const old = panels.get(from);
        set(old, "--menu-shift", -way * SHIFT);
        old.classList.remove("on");
        if (!showing(panel)) snap(panel, () => set(panel, "--menu-shift", way * SHIFT));
        fit(name);
        panel.classList.add("on");
      } else {
        // it was draining from this very panel, and turns back
        wet(name, 0);
      }
      shell.classList.add("open");
      glide(item);
    };

    const close = () => {
      clearTimeout(openTimer);
      clearTimeout(closeTimer);
      if (!current) return;
      const item = trigger(current);
      item.classList.remove("menu-open");
      item.setAttribute("aria-expanded", "false");
      current = null;
      shell.classList.remove("open");
      glide(hovered);
    };

    // the finger lifts (a tap: the link is followed) or moves off (a scroll) before the hold is up
    const letGo = (moved) => {
      if (!hold) return;
      clearTimeout(hold.timer);
      hold.item.classList.remove("holding");
      hold = null;
      if (moved && !held) glide(current ? trigger(current) : hovered);
    };

    for (const item of triggers) {
      const name = item.dataset.menu;
      item.addEventListener("pointerenter", (e) => {
        if (e.pointerType !== "mouse") return;
        clearTimeout(closeTimer);
        clearTimeout(openTimer);
        if (current !== name) openTimer = setTimeout(() => show(name), current ? SWITCH_DELAY : OPEN_DELAY);
      });
      item.addEventListener("pointerleave", (e) => {
        if (e.pointerType !== "mouse") return;
        clearTimeout(openTimer);
        if (current) closeTimer = setTimeout(close, CLOSE_DELAY);
      });
      item.addEventListener("pointerdown", (e) => {
        held = false;
        if (e.pointerType === "mouse" || !e.isPrimary) return;
        letGo(false);
        const press = hold = { item, id: e.pointerId, x: e.clientX, y: e.clientY };
        item.classList.add("holding");
        glide(item);
        press.timer = setTimeout(() => {
          if (hold !== press) return;
          held = true;
          item.classList.remove("holding");
          show(name);
        }, HOLD);
      });
      item.addEventListener("pointermove", (e) => {
        if (hold && hold.item === item && e.pointerId === hold.id && !held && Math.hypot(e.clientX - hold.x, e.clientY - hold.y) > 10) letGo(true);
      });
      item.addEventListener("pointerup", (e) => { if (hold && e.pointerId === hold.id) letGo(false); });
      item.addEventListener("pointercancel", (e) => { if (hold && e.pointerId === hold.id) letGo(true); });
      // the hold opened the panel: lifting the finger does not follow the link as well, and the
      // browser's long-press menu (or a drag of the link) does not come up
      item.addEventListener("click", (e) => {
        if (held && e.detail !== 0) {
          e.preventDefault();
          held = false;
        }
      });
      item.addEventListener("contextmenu", (e) => { if (hold || held) e.preventDefault(); });
      item.addEventListener("dragstart", (e) => { if (hold || held) e.preventDefault(); });
      item.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowDown") return;
        e.preventDefault();
        show(name);
        const first = panels.get(name).querySelector("a");
        if (first) first.focus();
      });
    }

    // the pill follows the mouse along the bar, and goes back to the open item (or away) once
    // the mouse has left the items
    for (const link of links) {
      link.addEventListener("pointerenter", (e) => {
        if (e.pointerType !== "mouse") return;
        clearTimeout(leaveTimer);
        hovered = link;
        glide(link);
      });
      link.addEventListener("pointerleave", (e) => {
        if (e.pointerType !== "mouse") return;
        hovered = null;
        clearTimeout(leaveTimer);
        leaveTimer = setTimeout(() => glide(current ? trigger(current) : null), LEAVE_DELAY);
      });
    }

    shell.addEventListener("pointerenter", (e) => {
      if (e.pointerType !== "mouse") return;
      clearTimeout(closeTimer);
      clearTimeout(openTimer);
    });
    shell.addEventListener("pointerleave", (e) => {
      if (e.pointerType === "mouse" && current) closeTimer = setTimeout(close, CLOSE_DELAY);
    });
    for (const [name, panel] of panels) {
      panel.addEventListener("keydown", (e) => {
        if (e.key !== "Escape") return;
        close();
        trigger(name).focus();
      });
      panel.addEventListener("focusout", (e) => {
        if (current === name && !panel.contains(e.relatedTarget) && e.relatedTarget !== trigger(name)) close();
      });
    }
    // a press anywhere but on the surface or the items closes it
    document.addEventListener("pointerdown", (e) => {
      if (current && !shell.contains(e.target) && !triggers.some((t) => t.contains(e.target))) close();
    });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    // a resize, or a font swapping in, refits the surface and the pill at once
    if (window.ResizeObserver) {
      const refit = () => {
        if (current) snap(shell, () => fit(current));
        if (pillOn) glide(pillOn, true);
      };
      const watch = new ResizeObserver(refit);
      watch.observe(header);
      for (const panel of panels.values()) watch.observe(panel);
    }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run);
  else run();
})();
