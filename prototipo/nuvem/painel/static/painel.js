// Painel acessivel (RT-21). Sem innerHTML com dados: tudo entra como texto
// (textContent), entao nada vindo do banco vira codigo na pagina (XSS).
"use strict";

const $ = (id) => document.getElementById(id);
const aviso = (msg) => { $("aviso").textContent = msg; };
let permissoes = [];

const NOMES_ESPACO = { centro: "Centro Comunitário", escola: "Escola", ubs: "UBS", horta: "Horta e Cozinha", abrigo: "Abrigo" };
const NOMES_STATUS = { executado: "Feito", aguardando_aprovacao: "Esperando aprovação", aprovado: "Aprovado", negado: "Negado" };

// ---------------------------------------------------------------- tema
function aplicarTema(tema) {
  document.documentElement.dataset.tema = tema;
  $("tema").setAttribute("aria-pressed", String(tema === "escuro"));
  $("tema").textContent = tema === "escuro" ? "Usar tema claro" : "Usar tema escuro";
  try { localStorage.setItem("tema", tema); } catch (_) { /* sem armazenamento: segue */ }
}
let temaSalvo = null;
try { temaSalvo = localStorage.getItem("tema"); } catch (_) { /* ignora */ }
aplicarTema(temaSalvo || (matchMedia("(prefers-color-scheme: dark)").matches ? "escuro" : "claro"));
$("tema").addEventListener("click", () =>
  aplicarTema(document.documentElement.dataset.tema === "escuro" ? "claro" : "escuro"));

// ---------------------------------------------------------------- api
async function api(metodo, url, corpo) {
  const r = await fetch(url, {
    method: metodo,
    headers: corpo ? { "Content-Type": "application/json" } : {},
    body: corpo ? JSON.stringify(corpo) : undefined,
    credentials: "same-origin",
  });
  let dados = {};
  try { dados = await r.json(); } catch (_) { /* resposta sem JSON (ex.: bloqueio do WAF) */ }
  if (!r.ok) {
    const msg = { 400: "Algum campo está em formato errado.", 401: "Você precisa entrar de novo.",
      403: "Seu perfil não tem permissão para isso.", 429: "Muitas tentativas. Espere 5 minutos." }[r.status];
    throw new Error(dados.erro || msg || "Não foi possível concluir. Tente de novo.");
  }
  return dados;
}

function linha(tbody, celulas) {
  const tr = document.createElement("tr");
  for (const c of celulas) {
    const td = document.createElement("td");
    if (c instanceof Node) td.appendChild(c); else td.textContent = c ?? "";
    tr.appendChild(td);
  }
  tbody.appendChild(tr);
}

function quando(iso) {
  return new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

// ---------------------------------------------------------------- telas
function situacao(s) {
  const span = document.createElement("span");
  let ruim = false;
  if (s.recurso === "ambiente" && s.dispositivo === "ubs-geladeira") ruim = s.valor < 2 || s.valor > 8;
  if (s.recurso === "agua") ruim = s.valor < 15;
  span.className = ruim ? "ruim" : "ok";
  span.textContent = ruim ? "Atenção: fora da faixa segura" : "Normal";
  return span;
}

async function carregarSensores() {
  const tbody = $("tabela-sensores").querySelector("tbody");
  tbody.replaceChildren();
  const { sensores } = await api("GET", "/telemetria");
  if (!sensores.length) linha(tbody, ["—", "Nenhuma leitura recebida ainda", "", "", ""]);
  for (const s of sensores) {
    const unidade = s.recurso === "ambiente" ? " °C" : (s.recurso === "acesso" ? "" : " %");
    linha(tbody, [NOMES_ESPACO[s.espaco] || s.espaco, s.dispositivo, s.recurso, `${s.valor}${unidade}`, situacao(s)]);
  }
}

async function carregarComandos() {
  const tbody = $("tabela-cmd").querySelector("tbody");
  tbody.replaceChildren();
  const { comandos } = await api("GET", "/comandos");
  for (const c of comandos) {
    let decisao = c.aprovador ? `${c.aprovador} em ${quando(c.decidido_em)}` : "";
    if (c.status === "aguardando_aprovacao" && permissoes.includes("comando:aprovar")) {
      const box = document.createElement("span");
      for (const [rotulo, aprovar] of [["Aprovar", true], ["Negar", false]]) {
        const b = document.createElement("button");
        b.type = "button"; b.className = "secundario"; b.textContent = `${rotulo} nº ${c.id}`;
        b.addEventListener("click", async () => {
          try { await api("POST", `/atuador/${c.id}/decisao`, { aprovar }); aviso(`Pedido nº ${c.id}: ${aprovar ? "aprovado" : "negado"}.`); carregarComandos(); }
          catch (e) { aviso(e.message); }
        });
        box.appendChild(b);
      }
      decisao = box;
    }
    linha(tbody, [String(c.id), c.solicitante, c.acao, c.alvo, NOMES_STATUS[c.status] || c.status, decisao]);
  }
}

function mostrarArea(dados) {
  permissoes = dados.permissoes || [];
  $("secao-login").hidden = true;
  $("area").hidden = false;
  $("sair").hidden = false;
  $("quem").textContent = `Você entrou como ${$("login").value} (perfil: ${dados.perfil}).`;
  $("secao-atuador").hidden = !permissoes.includes("atuador:baixo");
  $("secao-comandos").hidden = !permissoes.includes("comando:ler");
  $("conteudo").focus();
  carregarSensores().catch((e) => aviso(e.message));
  if (!$("secao-comandos").hidden) carregarComandos().catch((e) => aviso(e.message));
}

// ---------------------------------------------------------------- eventos
$("form-login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  try {
    const dados = await api("POST", "/login", { login: f.get("login"), senha: f.get("senha"), totp: f.get("totp") });
    aviso("");
    mostrarArea(dados);
  } catch (e) { aviso(e.message); }
});

$("sair").addEventListener("click", async () => {
  await api("POST", "/logout").catch(() => {});
  location.reload();
});

$("atualizar").addEventListener("click", () => carregarSensores().then(() => aviso("Leituras atualizadas.")).catch((e) => aviso(e.message)));

$("form-hist").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const q = new URLSearchParams();
  if (f.get("espaco")) q.set("espaco", f.get("espaco"));
  if (f.get("dispositivo")) q.set("dispositivo", f.get("dispositivo"));
  const tbody = $("tabela-hist").querySelector("tbody");
  tbody.replaceChildren();
  try {
    const { historico, total } = await api("GET", `/historico?${q}`);
    for (const h of historico) linha(tbody, [quando(h.ts), NOMES_ESPACO[h.espaco] || h.espaco, h.dispositivo, h.evento]);
    aviso(`${total} registro(s) encontrado(s).`);
  } catch (e) { aviso(e.message); }
});

$("form-atu").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  try {
    const r = await api("POST", "/atuador", { acao: f.get("acao"), alvo: f.get("alvo") });
    aviso(r.status === "executado" ? `Comando nº ${r.id} feito.` : `Comando nº ${r.id} está esperando outra pessoa da coordenação aprovar.`);
    if (!$("secao-comandos").hidden) carregarComandos();
  } catch (e) { aviso(e.message); }
});
