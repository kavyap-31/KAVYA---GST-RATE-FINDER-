import io, os, re, hmac, hashlib, secrets, sqlite3
from pathlib import Path
from datetime import date, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

import streamlit as st
import pandas as pd
from docx import Document
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "gst_finder.sqlite3"
DISCLAIMER = ("GST FINDER IS AN EDUCATIONAL TOOL, NOT AN OFFICIAL GOVERNMENT PLATFORM OR "
"SUBSTITUTE FOR PROFESSIONAL TAX ADVICE. VERIFY ALL GST RATES, CLASSIFICATIONS AND "
"VALUATION METHODS AGAINST CURRENT OFFICIAL NOTIFICATIONS BEFORE MAKING TAX OR BUSINESS DECISIONS.")
APP_VERSION = "1.0.0"

# Only selected examples supported by the supplied research plus the cited 2025 official notifications.
# This is intentionally NOT represented as a complete GST tariff.
SEED_RATES = [
 dict(product="Fresh milk / pasteurised milk", aliases="milk fresh pasteurised separated milk cream", category="Dairy",
 manufacturer="", hsn="0401", description="Fresh milk and pasteurised milk, including separated milk; milk and cream, not concentrated and not containing added sugar or other sweetening matter.", gst="0", cess="0", status="Exempt", source="Notification No. 10/2025-Central Tax (Rate), 17-09-2025, Schedule entry 15", source_url="https://egazette.gov.in/WriteReadData/2025/266210.pdf", effective="2025-09-22", verified=1),
 dict(product="UHT milk", aliases="milk uht ultra high temperature long life", category="Dairy", manufacturer="", hsn="0401", description="Ultra-high temperature (UHT) milk under heading 0401.", gst="0", cess="0", status="Exempt", source="Notification No. 10/2025-Central Tax (Rate), 17-09-2025, Schedule entry 15", source_url="https://egazette.gov.in/WriteReadData/2025/266210.pdf", effective="2025-09-22", verified=1),
 dict(product="Condensed milk", aliases="milk condensed sweetened concentrated", category="Dairy", manufacturer="", hsn="0402 91 10; 0402 99 20", description="Condensed milk. Do not apply this entry to fresh milk, UHT milk or other milk preparations without checking the exact tariff description.", gst="5", cess="0", status="Taxable", source="Notification No. 9/2025-Central Tax (Rate), 17-09-2025; 56th GST Council rate-change schedule", source_url="https://egazette.gov.in/WriteReadData/2025/266209.pdf", effective="2025-09-22", verified=1),
]

def db():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, pw_hash TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rates(id INTEGER PRIMARY KEY, product TEXT NOT NULL, aliases TEXT DEFAULT '', category TEXT DEFAULT '', manufacturer TEXT DEFAULT '', hsn TEXT DEFAULT '', description TEXT DEFAULT '', gst TEXT NOT NULL, cess TEXT DEFAULT '0', status TEXT DEFAULT 'Unverified', source TEXT DEFAULT '', source_url TEXT DEFAULT '', effective TEXT DEFAULT '', verified INTEGER DEFAULT 0, version TEXT DEFAULT '1');
        CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL, payload TEXT DEFAULT '', created TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS valuation_log(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, rule TEXT NOT NULL, summary TEXT NOT NULL, created TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        """)
        if c.execute("SELECT COUNT(*) FROM rates").fetchone()[0] == 0:
            c.executemany("""INSERT INTO rates(product,aliases,category,manufacturer,hsn,description,gst,cess,status,source,source_url,effective,verified,version)
            VALUES(:product,:aliases,:category,:manufacturer,:hsn,:description,:gst,:cess,:status,:source,:source_url,:effective,:verified,'2025.09')""", SEED_RATES)

def D(x, label="Amount"):
    try:
        v=Decimal(str(x).strip())
        if not v.is_finite(): raise InvalidOperation
        return v
    except Exception:
        raise ValueError(f"{label}: enter a valid number.")

def q2(x):
    return D(x).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def money(x):
    return f"₹{q2(x):,.2f}"

def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000).hex()

def add_history(kind, summary, payload=""):
    uid=st.session_state.get("user_id")
    if uid:
        with db() as c:
            c.execute("INSERT INTO history(user_id,kind,summary,payload,created) VALUES(?,?,?,?,?)",
                      (uid,kind,summary,payload,datetime.now().isoformat(timespec="seconds")))

def account_ui():
    st.sidebar.markdown("### Account")
    if st.session_state.get("username"):
        st.sidebar.success("Signed in: "+st.session_state.username)
        if st.sidebar.button("Sign out"):
            st.session_state.user_id=None; st.session_state.username=None; st.rerun()
        return
    mode=st.sidebar.radio("Access",["Guest","Sign in","Register"],key="account_mode")
    if mode=="Guest":
        st.session_state.user_id=None; st.session_state.username=None
    elif mode=="Register":
        u=st.sidebar.text_input("Username",key="reg_u")
        p=st.sidebar.text_input("Password (12+ characters)",type="password",key="reg_p")
        if st.sidebar.button("Create account"):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}",u or ""):
                st.sidebar.error("Username must be 3–40 letters, numbers, dots, underscores or hyphens.")
            elif len(p)<12:
                st.sidebar.error("Use at least 12 characters.")
            else:
                salt=secrets.token_bytes(16)
                try:
                    with db() as c:
                        c.execute("INSERT INTO users(username,salt,pw_hash,created) VALUES(?,?,?,?)",
                                  (u,salt,hash_pw(p,salt),datetime.now().isoformat()))
                    st.sidebar.success("Account created. Choose Sign in.")
                except sqlite3.IntegrityError:
                    st.sidebar.error("Username already exists.")
    else:
        u=st.sidebar.text_input("Username",key="login_u")
        p=st.sidebar.text_input("Password",type="password",key="login_p")
        if st.sidebar.button("Sign in"):
            with db() as c: row=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
            if row and hmac.compare_digest(hash_pw(p,row["salt"]),row["pw_hash"]):
                st.session_state.user_id=row["id"]; st.session_state.username=row["username"]; st.rerun()
            else: st.sidebar.error("Incorrect username or password.")

def norm(s):
    return " ".join(re.sub(r"[^a-z0-9]+"," ",str(s or "").casefold()).split())

def search_rates(product, hsn, category, manufacturer):
    terms=norm(product).split()
    h=norm(hsn); m=norm(manufacturer)
    with db() as c: rows=c.execute("SELECT * FROM rates ORDER BY product").fetchall()
    found=[]
    for r in rows:
        if category!="All categories" and r["category"]!=category: continue
        if m and m not in norm(r["manufacturer"]): continue
        if h and h not in norm(r["hsn"]): continue
        blob=norm(" ".join([r["product"],r["aliases"],r["description"],r["hsn"],r["category"],r["manufacturer"]]))
        if not terms and not h: continue
        if terms and not all(t in blob for t in terms): continue
        score=sum(1 for t in terms if t in norm(r["product"]))*5
        if norm(r["product"])==norm(product): score+=100
        found.append((score,r))
    return [r for _,r in sorted(found,key=lambda x:(-x[0],x[1]["product"]))]

def page_home():
    st.title("GST FINDER")
    st.subheader("Indian GST rate, valuation and calculation workspace")
    st.write("Search a source-linked rate register, calculate GST, review valuation checkpoints and create calculation previews.")
    a,b,c=st.columns(3)
    with db() as conn:
        a.metric("Rate entries",conn.execute("SELECT COUNT(*) FROM rates").fetchone()[0])
        b.metric("Verified entries",conn.execute("SELECT COUNT(*) FROM rates WHERE verified=1").fetchone()[0])
        c.metric("App version",APP_VERSION)
    st.info("The starter register is intentionally limited. A missing search result is not evidence that a supply is exempt or outside GST.")
    st.markdown("### Popular starter searches")
    for term in ["MILK","UHT milk","Condensed milk"]:
        if st.button(term,key="popular_"+term):
            st.session_state.search_prefill=term
            st.session_state.page="GST RATE FINDER"
            st.rerun()

def page_finder():
    st.header("GST Rate Finder")
    pref=st.session_state.pop("search_prefill","")
    p=st.text_input("Product name or description",value=pref,placeholder="e.g. milk, shampoo, mobile phone")
    h=st.text_input("Optional HSN / SAC code")
    with db() as c:
        cats=["All categories"]+[x[0] for x in c.execute("SELECT DISTINCT category FROM rates WHERE category<>'' ORDER BY category")]
    category=st.selectbox("Category",cats)
    manufacturer=st.text_input("Manufacturer (optional)")
    if st.button("SEARCH GST RATE",type="primary",use_container_width=True):
        if not p.strip() and not h.strip(): st.warning("Enter a product name or HSN/SAC code.")
        else:
            results=search_rates(p,h,category,manufacturer)
            st.session_state.finder_results=[dict(x) for x in results]
            st.session_state.finder_query=p or h
            add_history("Rate search",p or h)
    results=st.session_state.get("finder_results")
    if results is not None:
        if not results:
            st.error("NO MATCH IN THE CURRENT RATE REGISTER. This does not mean the product is exempt, nil-rated, zero-rated or non-GST. Check the correct HSN/SAC and add a source-verified entry in Rate Register.")
        else:
            st.success(f"{len(results)} matching entry/entries. Read the complete description and conditions.")
            for r in results:
                with st.container(border=True):
                    st.subheader(r["product"])
                    st.write(f'**HSN/SAC:** {r["hsn"]}  |  **Category:** {r["category"] or "Not recorded"}')
                    st.write(r["description"])
                    x,y,z=st.columns(3)
                    x.metric("GST",r["gst"]+"%")
                    y.metric("CGST / SGST",f'{D(r["gst"])/2}% / {D(r["gst"])/2}%')
                    z.metric("IGST",r["gst"]+"%")
                    st.write(f'**Cess:** {r["cess"]}%  |  **Supply status:** {r["status"]}')
                    st.write(f'**Effective date:** {r["effective"] or "Not recorded"}  |  **Verification:** {"Source entered as verified" if r["verified"] else "UNVERIFIED"}')
                    st.caption("Source: "+(r["source"] or "Not recorded"))
                    if r["source_url"].startswith("https://"): st.markdown("[Open cited source]("+r["source_url"]+")")
                    st.warning("App records are not a substitute for checking the current consolidated notification, tariff notes, product composition, packaging/label conditions and amendments.")
                    if st.button("Use this GST rate in calculator",key=f'use_{r["id"]}'):
                        st.session_state.calc_rate=r["gst"]
                        st.session_state.calc_hsn=r["hsn"]
                        st.session_state.page="GST CALCULATOR"; st.rerun()

def page_rate_register():
    st.header("GST Rate Register")
    st.warning("Add only after checking the current official notification and exact HSN/SAC description. New manual entries are always marked UNVERIFIED.")
    with st.form("rate_add",clear_on_submit=True):
        product=st.text_input("Product / service name *")
        aliases=st.text_input("Search keywords / alternate names")
        category=st.text_input("Category")
        manufacturer=st.text_input("Manufacturer")
        hsn=st.text_input("HSN / SAC *")
        description=st.text_area("Full tariff description and conditions *")
        gst=st.text_input("GST rate (%)")
        cess=st.text_input("Cess (%)","0")
        status=st.selectbox("Classification status",["Taxable","Exempt","Nil-rated","Zero-rated","Non-GST","Unverified"])
        effective=st.date_input("Effective date",value=date.today())
        source=st.text_input("Official source / notification reference *")
        url=st.text_input("Official source URL")
        submit=st.form_submit_button("Save as unverified")
    if submit:
        try:
            gr,cr=D(gst,"GST rate"),D(cess,"Cess")
            if not product.strip() or not hsn.strip() or not description.strip() or not source.strip(): raise ValueError("Product, HSN/SAC, description and official source are required.")
            if min(gr,cr)<0 or max(gr,cr)>100: raise ValueError("Rates must be between 0 and 100.")
            if url and not url.startswith("https://"): raise ValueError("Source URL must start with https://")
            with db() as c:
                c.execute("""INSERT INTO rates(product,aliases,category,manufacturer,hsn,description,gst,cess,status,source,source_url,effective,verified,version)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,'manual-1')""",(product,aliases,category,manufacturer,hsn,description,str(gr),str(cr),status,source,url,effective.isoformat()))
            st.success("Saved as UNVERIFIED. It will be labelled accordingly in search.")
        except ValueError as e: st.error(str(e))
    with db() as c: rows=c.execute("SELECT id,product,hsn,gst,cess,status,effective,source,verified FROM rates ORDER BY product").fetchall()
    st.dataframe(pd.DataFrame([dict(r) for r in rows]),use_container_width=True,hide_index=True)
    st.caption("Production legal updates should be versioned, reviewed and approved by a GST professional before being marked verified.")

def page_calculator():
    st.header("GST Calculator")
    if "calc_rate" not in st.session_state: st.session_state.calc_rate="18"
    if "calc_hsn" not in st.session_state: st.session_state.calc_hsn=""
    mode=st.radio("Amount type",["Taxable value (exclusive)","Invoice total (inclusive)"],horizontal=True)
    supply=st.radio("Place-of-supply tax type",["Intra-state: CGST + SGST","Inter-state: IGST"],horizontal=True)
    amount=st.text_input("Amount (₹)","1000")
    hsn=st.text_input("HSN / SAC (optional)",value=st.session_state.calc_hsn)
    rate=st.text_input("GST rate (%)",value=st.session_state.calc_rate)
    cess=st.text_input("Cess rate (%)","0")
    if st.button("CALCULATE GST",type="primary"):
        try:
            a,g,c=D(amount),D(rate,"GST rate"),D(cess,"Cess rate")
            if a<0 or g<0 or c<0 or g>100 or c>100: raise ValueError("Amount and rates must be non-negative; rates cannot exceed 100%.")
            taxable=a*100/(100+g+c) if mode.startswith("Invoice") else a
            tax=taxable*g/100; ce=taxable*c/100
            cg=tax/2 if supply.startswith("Intra") else Decimal(0)
            sg=cg; ig=tax if supply.startswith("Inter") else Decimal(0)
            total=taxable+tax+ce
            result={"Taxable value":money(taxable),"CGST":money(cg),"SGST":money(sg),"IGST":money(ig),"Cess":money(ce),"Total payable":money(total)}
            st.session_state.bill_result=result
            st.session_state.bill_meta={"hsn":hsn,"gst_rate":str(g),"cess_rate":str(c),"supply":supply,"method":mode}
            st.table({"Particulars":list(result.keys()),"Amount":list(result.values())})
            add_history("GST calculation",f"{money(a)} at {g}% GST; {supply}",str(result))
        except (ValueError,InvalidOperation,ZeroDivisionError) as e: st.error(str(e))

def page_valuation():
    st.header("GST Valuation — Section 15 and Rules 27–33")
    st.warning("This is a guided fact checklist, not a legal opinion or automated determination of taxable value. Rules 32 and 32A specialist supplies are not automated here.")
    st.markdown("### Section 15 — transaction value and adjustments")
    price=st.text_input("Price actually paid/payable (₹)","0")
    taxes=st.text_input("Non-GST taxes/fees/charges includible (₹)","0")
    recipient_exp=st.text_input("Expenses incurred by recipient on supplier's behalf (₹)","0")
    incidental=st.text_input("Supplier incidental expenses / commission / packing (₹)","0")
    interest=st.text_input("Interest / late fee / penalty for delayed payment (₹)","0")
    subsidy=st.text_input("Non-government price-linked subsidy (₹)","0")
    gov_sub=st.text_input("Government subsidy (₹) — shown separately, not added by this field","0")
    discount_pre=st.text_input("Pre-supply discount recorded on invoice (₹)","0")
    discount_post=st.text_input("Post-supply discount claimed (₹)","0")
    st.markdown("### Choose the special valuation issue")
    rule=st.selectbox("Applicable workflow",["Section 15 — ordinary transaction value","Rule 27 — non-monetary consideration","Rule 28 — related / distinct persons","Rule 29 — principal-agent goods","Rule 30 — cost plus 10%","Rule 31 — residual method","Rule 33 — pure-agent expenditure"])
    st.markdown("### Rule-specific facts")
    facts={}
    if rule=="Rule 27 — non-monetary consideration":
        facts["omv"]=st.text_input("Open market value, if available (₹)","")
        facts["money"]=st.text_input("Money consideration (₹)","")
        facts["nonmoney"]=st.text_input("Money value of non-monetary consideration (₹)","")
        facts["like"]=st.text_input("Like kind and quality value (₹)","")
        facts["cost"]=st.text_input("Cost of supply (₹)","")
    elif rule=="Rule 28 — related / distinct persons":
        facts["omv"]=st.text_input("Open market value (₹)","")
        facts["like"]=st.text_input("Like kind and quality value (₹)","")
        facts["further"]=st.checkbox("Goods intended for further supply as such; consider prescribed 90% option")
        facts["resale"]=st.text_input("Recipient's price to unrelated customer (₹)","")
        facts["itc"]=st.checkbox("Recipient eligible for full input tax credit")
        facts["cost"]=st.text_input("Cost of supply (₹)","")
    elif rule=="Rule 29 — principal-agent goods":
        facts["omv"]=st.text_input("Open market value of goods (₹)","")
        facts["resale"]=st.text_input("Agent's price to unrelated customer for like kind/quality (₹)","")
        facts["option90"]=st.checkbox("Supplier elects 90% option, if statutory conditions met")
        facts["cost"]=st.text_input("Cost of supply if primary method unavailable (₹)","")
    elif rule=="Rule 30 — cost plus 10%":
        facts["cost"]=st.text_input("Cost of production/acquisition/provision (₹)","")
    elif rule=="Rule 31 — residual method":
        facts["basis"]=st.text_area("Explain reasonable means and evidence consistent with Section 15 and Chapter IV")
        facts["amount"]=st.text_input("Proposed residual value (₹)","")
    elif rule=="Rule 33 — pure-agent expenditure":
        facts["recovery"]=st.text_input("Amount recovered from recipient (₹)","")
        facts["actual"]=st.text_input("Actual third-party expenditure (₹)","")
        facts["recipient_liability"]=st.checkbox("Recipient is liable to pay the third party")
        facts["authorised"]=st.checkbox("Supplier authorised by recipient to make payment")
        facts["separate"]=st.checkbox("Recipient knows goods/services procured from third party")
        facts["separate_invoice"]=st.checkbox("Separately indicated in supplier's invoice")
        facts["only_actual"]=st.checkbox("Only actual amount incurred is recovered")
        facts["own_use"]=st.checkbox("Supplier procures and uses the item for own interest (check: should generally be false)")
    if st.button("REVIEW VALUATION FACTS",type="primary"):
        try:
            p=D(price,"Price"); inc=sum((D(x,label) for x,label in [(taxes,"Other taxes"),(recipient_exp,"Recipient expenses"),(incidental,"Incidental expenses"),(interest,"Interest/late fee"),(subsidy,"Subsidy")]),Decimal(0))
            pre=D(discount_pre,"Pre-supply discount"); post=D(discount_post,"Post-supply discount")
            if min(p,inc,pre,post)<0: raise ValueError("Amounts cannot be negative.")
            notes=[f"Base transaction value entered: {money(p)}"]
            if gov_sub.strip() and D(gov_sub,"Government subsidy")<0: raise ValueError("Government subsidy cannot be negative.")
            notes.append(f"Section 15 potential additions entered: {money(inc)}; verify each statutory condition and whether already included.")
            if pre: notes.append(f"Pre-supply discount: {money(pre)} — exclusion requires it to be given before/at supply and recorded on invoice.")
            if post: notes.append(f"Post-supply discount: {money(post)} — exclusion requires prior agreement, invoice linkage and recipient ITC reversal under Section 15(3)(b).")
            if rule.startswith("Section 15"):
                notes.append("Transaction value applies only if supplier and recipient are not related and price is sole consideration, subject to statutory inclusions/exclusions.")
                indicative=p+inc-pre
            elif rule.startswith("Rule 27"):
                vals=[("Open market value",facts["omv"]),("Money plus non-money value",None),("Like kind and quality",facts["like"]),("Cost plus 10%",None)]
                notes.append("Rule 27 sequence: open market value; money consideration plus money value of non-money consideration; like kind and quality; cost plus 10%; then Rule 31 residual method.")
                if facts["omv"].strip(): indicative=D(facts["omv"],"OMV")
                elif facts["money"].strip() and facts["nonmoney"].strip(): indicative=D(facts["money"])+D(facts["nonmoney"])
                elif facts["like"].strip(): indicative=D(facts["like"])
                elif facts["cost"].strip(): indicative=D(facts["cost"])*Decimal("1.10")
                else: indicative=None
            elif rule.startswith("Rule 28"):
                notes.append("Rule 28 sequence: open market value; like kind and quality; cost plus 10%; then Rule 31. If goods are for further supply as such, assess the prescribed 90% option. Where recipient has full ITC, invoice value is deemed OMV subject to the rule.")
                indicative=D(facts["omv"]) if facts["omv"].strip() else (D(facts["like"]) if facts["like"].strip() else (D(facts["cost"])*Decimal("1.10") if facts["cost"].strip() else None))
                if facts["itc"]: notes.append("Full ITC box checked: assess invoice value deeming provision and documentary eligibility.")
                if facts["further"] and facts["resale"].strip(): notes.append("90% comparison amount entered: "+money(D(facts["resale"])*Decimal("0.90"))+"; confirm option and conditions.")
            elif rule.startswith("Rule 29"):
                notes.append("Rule 29 is for goods supplied through a principal-agent relationship: open market value OR supplier's option of 90% of agent's onward price to unrelated customer; if unavailable, cost plus 10%, then Rule 31.")
                indicative=D(facts["omv"]) if facts["omv"].strip() else (D(facts["resale"])*Decimal("0.90") if facts["option90"] and facts["resale"].strip() else (D(facts["cost"])*Decimal("1.10") if facts["cost"].strip() else None))
            elif rule.startswith("Rule 30"):
                notes.append("Rule 30: value is 110% of cost of production/manufacture/acquisition or provision of services, as applicable.")
                indicative=D(facts["cost"])*Decimal("1.10") if facts["cost"].strip() else None
            elif rule.startswith("Rule 31"):
                notes.append("Rule 31 is residual: use reasonable means consistent with Section 15 and Chapter IV; record evidence and assumptions.")
                indicative=D(facts["amount"]) if facts["amount"].strip() else None
            else:
                tests=[facts["recipient_liability"],facts["authorised"],facts["separate"],facts["separate_invoice"],facts["only_actual"],not facts["own_use"]]
                notes.append("Rule 33 pure-agent exclusion is conditional. Checklist must satisfy all applicable conditions; reimbursement alone is not enough.")
                notes.append("Rule 33 checklist: recipient liability, prior authorisation, recipient's receipt/benefit, separate invoice disclosure, actual-cost-only recovery, and supplier does not use the procurement for own interest.")
                indicative=None
                if all(tests) and facts["recovery"].strip() and facts["actual"].strip():
                    if D(facts["recovery"])==D(facts["actual"]): notes.append("Entered checklist is internally consistent; professional verification of every Rule 33 condition remains required.")
                    else: notes.append("Recovery differs from actual expenditure: do not exclude the difference as pure-agent disbursement.")
                else: notes.append("One or more checklist conditions are not confirmed. Do not exclude this expenditure.")
            if indicative is not None:
                notes.append("Indicative method value from supplied facts (before final Section 15 adjustments): "+money(indicative))
                st.metric("Indicative value from selected method",money(indicative))
            else:
                st.info("Insufficient inputs for an indicative method value; no amount has been invented.")
            for n in notes: st.write("• "+n)
            summary=" | ".join(notes)
            uid=st.session_state.get("user_id")
            if uid:
                with db() as c: c.execute("INSERT INTO valuation_log(user_id,rule,summary,created) VALUES(?,?,?,?)",(uid,rule,summary,datetime.now().isoformat()))
            add_history("Valuation review",rule,summary)
            st.error("Review the current Act, Rules, notifications and facts with a GST professional before adopting a taxable value.")
        except (ValueError,InvalidOperation) as e: st.error(str(e))

def page_bill():
    st.header("Bill / Calculation Preview")
    data=st.session_state.get("bill_result")
    if not data: st.info("Calculate GST first."); return
    meta=st.session_state.get("bill_meta",{})
    st.caption("Calculation preview only — not necessarily a tax invoice.")
    st.write("HSN/SAC:",meta.get("hsn","Not entered"),"| GST rate:",meta.get("gst_rate",""),"%")
    st.table({"Particulars":list(data.keys()),"Amount":list(data.values())})
    lines=["GST CALCULATION PREVIEW — NOT NECESSARILY A TAX INVOICE",
           "HSN/SAC: "+meta.get("hsn","Not entered"),"GST rate: "+meta.get("gst_rate","")+"%",
           "Supply type: "+meta.get("supply","")]
    lines += [f"{k}: {v}" for k,v in data.items()] + ["",DISCLAIMER]
    content="\n".join(lines)
    st.download_button("Download TXT",content,"gst_calculation_preview.txt","text/plain")
    buff=io.BytesIO(); pdf=canvas.Canvas(buff,pagesize=A4); y=800
    for line in lines:
        if y<50: pdf.showPage(); y=800
        pdf.drawString(40,y,line[:115]); y-=18
    pdf.save()
    st.download_button("Download PDF",buff.getvalue(),"gst_calculation_preview.pdf","application/pdf")
    doc=Document(); doc.add_heading(lines[0],0)
    for line in lines[1:]: doc.add_paragraph(line)
    b=io.BytesIO(); doc.save(b)
    st.download_button("Download DOCX",b.getvalue(),"gst_calculation_preview.docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document")

def page_history():
    st.header("History")
    uid=st.session_state.get("user_id")
    if not uid: st.info("Guest activity is not persisted. Sign in to save your searches and calculations."); return
    with db() as c: rows=c.execute("SELECT id,kind,summary,created FROM history WHERE user_id=? ORDER BY id DESC",(uid,)).fetchall()
    if rows: st.dataframe(pd.DataFrame([dict(r) for r in rows]),use_container_width=True,hide_index=True)
    else: st.info("No history yet.")
    if st.button("DELETE MY HISTORY"):
        with db() as c: c.execute("DELETE FROM history WHERE user_id=?",(uid,))
        st.success("Your history has been deleted."); st.rerun()

def page_info():
    st.header("Information and legal notes")
    st.markdown("""
**HSN / SAC:** Harmonised System of Nomenclature for goods / Services Accounting Code for services.

**CGST + SGST:** generally apply to intra-State supplies. **IGST:** generally applies to inter-State supplies, subject to place-of-supply rules.

**Distinct supply statuses:** exempt, nil-rated, zero-rated and non-GST are not interchangeable.

**Valuation:** Section 15 transaction value is subject to conditions, inclusions and exclusions. Rule 27 covers non-monetary consideration; Rule 28 related/distinct persons; Rule 29 principal-agent goods; Rule 30 cost plus 10%; Rule 31 residual method; Rule 33 pure-agent expenditure.

**Privacy:** guest search/calculation history is not saved. Registered-user history is stored in the local SQLite database. This sample does not provide production-grade multi-tenant hosting, encryption-at-rest, MFA, audit-grade access control or managed backups. Do not store PAN, Aadhaar, bank credentials or identifiable taxpayer documents.
""")
    st.warning("Rate coverage is limited to selected source-backed entries. The supplied CBIC schedule is dated 01-04-2023 and cannot be treated as the complete current schedule. Official notifications and amendments must be checked item by item.")
    st.markdown("**Official references:** [CBIC GST rates](https://cbic-gst.gov.in/hindi/gst-goods-services-rates.html) · [GST Council rate notifications](https://www.gstcouncil.gov.in/cgst-rate-notification) · [56th GST Council FAQ](https://gstcouncil.gov.in/sites/default/files/2025-09/faq_0.pdf)")

def main():
    st.set_page_config(page_title="GST Finder",page_icon="🧾",layout="wide")
    st.markdown("""<style>
    .stApp{background:#f4f7fb}.block-container{max-width:1250px;padding-top:1.2rem}
    h1,h2,h3{color:#174f86}
    [data-testid="stSidebar"]{background:#eaf1f8}
    div.stButton>button,div.stDownloadButton>button{background:#155da8;color:white;border-radius:8px;border:0}
    </style>""",unsafe_allow_html=True)
    init_db()
    if "user_id" not in st.session_state: st.session_state.user_id=None
    if "username" not in st.session_state: st.session_state.username=None
    if "page" not in st.session_state: st.session_state.page="HOME"
    st.title("🧾 GST FINDER")
    st.warning(DISCLAIMER)
    account_ui()
    options=["HOME","GST RATE FINDER","GST CALCULATOR","GST VALUATION","BILL PREVIEW","RATE REGISTER","HISTORY","INFO"]
    selected=st.sidebar.radio("Navigation",options,index=options.index(st.session_state.page) if st.session_state.page in options else 0)
    st.session_state.page=selected
    {"HOME":page_home,"GST RATE FINDER":page_finder,"GST CALCULATOR":page_calculator,
     "GST VALUATION":page_valuation,"BILL PREVIEW":page_bill,"RATE REGISTER":page_rate_register,
     "HISTORY":page_history,"INFO":page_info}[selected]()
if __name__=="__main__": main()
