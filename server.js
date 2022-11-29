//================================================================================ [공통] Express 라이브러리 import
const express = require('express');
//================================================================================ [공통] https 관련 라이브러리 import
const expressSanitizer = require("express-sanitizer");

const https = require("https");
const fs = require("fs");

const options = {
  key: fs.readFileSync("./secrets/cert.key"),
  cert: fs.readFileSync("./secrets/cert.crt"),
};

//================================================================================ [공통] dotenv 환경변수 등록
require('dotenv').config({ path:'./secrets/.env'})

//================================================================================ [공통] react router 관련 라이브러리 import
const path = require('path');

//================================================================================ [공통] passport 라이브러리 import
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');

//================================================================================ [공통] body-parser 라이브러리 import
const bodyParser= require('body-parser')
//================================================================================ [공통] connect-flash 라이브러리 import
const flash= require('connect-flash')

//================================================================================ [공통] axios AJAX 라이브러리 import
const { default: axios } = require('axios');

//================================================================================ [공통] maria DB 라이브러리 import
const {strFunc, insertFunc, batchInsertFunc, batchInsertOnDupliFunc, whereClause, truncateTable} = require ('./maria_db/mariadb');
const { type } = require('os');

//================================================================================ [공통] bcrypt 라이브러리 import
const bcrypt = require('bcrypt');
const saltRounds = 1;

//================================================================================ [공통] jwt 라이브러리 import
const jwt = require("jsonwebtoken");

//================================================================================ [공통] Express 객체 생성
const app = express();

//================================================================================ [공통 미들웨어] json
app.use(express.json({limit: '10mb'}))
//================================================================================ [공통 미들웨어] https 관련
app.use(express.urlencoded({ extended: true }));
app.use(expressSanitizer());
app.use("/", express.static("public"));

//================================================================================ [공통 미들웨어] body-parser
app.use(bodyParser.urlencoded({extended: true})) 
app.use(express.urlencoded({limit: '10mb', extended: true}))
//================================================================================ [공통 미들웨어] connect-flash
app.use(flash())

//================================================================================ [공통 미들웨어] passport
const expireTimeMinutes=20
app.use(session({secret : process.env.passport_secret_code, resave : false, saveUninitialized: false, cookie: { maxAge : expireTimeMinutes*60000 }, rolling:true})); //cookie: { maxAge : 60000 } 제외함
app.use(passport.initialize());
app.use(passport.session());
//================================================================================ [공통 미들웨어] react router 관련
app.use(express.static(path.join(__dirname, process.env.react_build_path)));

//================================================================================ [공통 기능] 서버실행
app.listen(5004, function() {
    console.log('listening on '+ 5004)
  })

//================================================================================ https 의존성으로 certificate와 private key로 새로운 서버를 시작
https.createServer(options, app).listen(process.env.PORT, () => {
  console.log('HTTPS server started on port '+ process.env.PORT)
});

  //================================================================================ [공통 기능] 로그인 증명
  app.post('/login', passport.authenticate('local', {successRedirect :"/logincheck",failureRedirect : '/fail', failureFlash : true}), function(req, res){
    res.redirect('/')
  });
  
  app.get('/logout', loginCheck,function(req,res){
    req.session.destroy(async() =>
    {
      res.clearCookie('connect.sid');

      let auditTrailRows=[]
      auditTrailRows.push([req.user.user_account,"로그아웃",""])
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

      res.redirect('/');
      
    });
  })

  app.get('/fail', function(req,res){
    res.json({success : false, flashMsg : req.session.flash.error.slice(-1)[0] })
    console.log(req.session.flash.error.slice(-1)[0])
  })
  
  app.get('/logincheck', loginCheck, function (req, res) {
    res.status(200).json({success : true, userInfo : req.user, expireTime:expireTimeMinutes})
  }) 
  
  function loginCheck(req, res, next) { 
    if (req.user) {
      next()
    } 
    else {
      res.json({success : false})
    } 
  } 
  
  passport.use(new LocalStrategy({
    usernameField: 'id',
    passwordField: 'pw',
    session: true,
    passReqToCallback: false,
  }, function (reqID, reqPW, done) {
    console.log("verifying user account ...")
    strFunc("SELECT * FROM tb_groupware_user WHERE user_account='"+reqID+"'")
      .then(async (rowResult)=>{
        if (rowResult.length<1)
        {
          console.log("This account is not exist")

          let auditTrailRows=[]
          auditTrailRows.push(['system',"존재하지 않은 계정 '"+reqID+"'으로 로그인 시도",""])
          await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

          return done(null, false, { message: "no user_account" })
        }
        else if (rowResult.length==1)
        {
          strFunc("SELECT user_account, user_auth, account_status, login_fail_count FROM tb_groupware_user WHERE user_account='"+reqID+"'")
          .then(async (authResult)=>{
            if(JSON.parse(authResult[0].account_status).length>0){
              if(authResult[0].account_status.indexOf('Lock')!=(-1)){
                console.log("This account is locked")

                let auditTrailRows=[]
                auditTrailRows.push([reqID,"잠겨있는 계정 '"+reqID+"'으로 로그인 시도",""])
                await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
  
                return done(null, false, { message: 'locked' })
              }
            }
            else if(JSON.parse(authResult[0].user_auth).length<1){
              console.log("This account is no auth")

              let auditTrailRows=[]
              auditTrailRows.push([reqID,"권한이 없는 계정 '"+reqID+"'으로 로그인 시도",""])
              await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

              return done(null, false, { message: 'no auth' })
            }
            else{
              if (bcrypt.compareSync(reqPW, rowResult[0].user_pw))
              {
                console.log("This account and PW was verified")

                let auditTrailRows=[]
                auditTrailRows.push([reqID,"로그인",""])
                await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
                strFunc("UPDATE tb_groupware_user SET login_fail_count = 0 WHERE user_account = '" + reqID + "'")
                return done(null, rowResult)
              }
              else
              {
                console.log("This account is valid but this PW is wrong.")
                let nowFailCount=0;
                if (!authResult[0].login_fail_count||authResult[0].login_fail_count<1){
                  strFunc("UPDATE tb_groupware_user SET login_fail_count = 1 WHERE user_account = '" + reqID + "'")
                  nowFailCount=1;
                }
                else if(authResult[0].login_fail_count==(5-1)){
                 let getAccountStat= JSON.parse(authResult[0].account_status)
                 getAccountStat.push({abb:"LockPw",att_name:"Lock by PW Incorrect"})
                 await strFunc("UPDATE tb_groupware_user SET account_status = '" + JSON.stringify(getAccountStat) +"' WHERE user_account = '" + reqID + "'")
                 nowFailCount=5;
                }
                else{
                  strFunc("UPDATE tb_groupware_user SET login_fail_count = " + (parseInt(authResult[0].login_fail_count)+1)+ " WHERE user_account = '" + reqID + "'")
                  nowFailCount = (parseInt(authResult[0].login_fail_count)+1);
                }
                let auditTrailRows=[]
                auditTrailRows.push([reqID,"로그인 실패 (잘못된 패스워드)",""])
                await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
                
                if (nowFailCount==5){
                  return done(null, false, { message: 'wrong PW ('+'max'+")" } )
                }
                else{
                  return done(null, false, { message: 'wrong PW ('+nowFailCount+")" } )
                }
              }
            }

          })
          .catch((err)=>{
            console.log(err)
          })
        }
      })

  }));
  
  passport.serializeUser(function (rowResult, done) {
    done(null,rowResult[0].user_account)
    console.log("Session was created.")
  });
  
  passport.deserializeUser(function (user_id, done) {
    strFunc("SELECT * FROM tb_groupware_user WHERE user_account='"+user_id+"'")
    .then((rowResult)=>{
  
      let user_auths = []
  
      JSON.parse(rowResult[0].user_auth).map((oneAuth,i)=>{
        user_auths.push(oneAuth.abb)
      })

      done(null, {
        user_account:rowResult[0].user_account,
        user_name:rowResult[0].user_name,
        user_auth:user_auths,
        secret_data : jwt.sign({data:"nothing"}, process.env.jwt_secret_key)
      })
    })
  
  });
  



  //================================================================================ [공통 기능] jwt 복호화 (개발중)
  app.get('/jwtverify', loginCheck, function(req,res){
    console.log(jwt.verify(req.query.token,  process.env.jwt_secret_key))
    res.json(jwt.verify(req.query.token,  process.env.jwt_secret_key))
  })

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getaudittrail', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT user_account, user_action, data, BIN_TO_UUID(uuid_binary) AS uuid_binary, action_datetime FROM tb_audit_trail " + await whereClause("tb_audit_trail",req.query.searchKeyWord) +" ORDER BY action_datetime DESC")
    .then((rowResult)=>{
      return {success:true, result:rowResult}})
    .catch((err)=>{
      return {success:false, result:err}})
    res.json(qryResult)
  });

    //================================================================================ [공통 기능] 비밀번호 수정 (reset_by, uuid_binary, user_account, 변경할 pw, 받아야함)
    app.put('/resetaccountpw',loginCheck,async function(req,res){
      let setArrys=[]
      let hasedPw = await bcryptHashing(req.body.user_pw)
      
      setArrys.push("user_pw='"+hasedPw+"'")
      setArrys.push("update_datetime=now()")

      let auditTrailRows=[]
      auditTrailRows.push(req.body.reset_by,"'" + req.body.user_account + "' 계정의 비밀번호 초기화",req.body.user_account)

      let qryResult = await strFunc("UPDATE tb_groupware_user SET "+ setArrys.join(",") + " WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
      .then(async (rowResult)=>{
        strFunc("UPDATE tb_groupware_user SET login_fail_count = 0 WHERE uuid_binary = UUID_TO_BIN('" + req.body.uuid_binary +"')")
        await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
        return {success:true, result:rowResult}
      })
      .catch((err)=>{return {success:false, result:err}})
      res.json(qryResult)
    })

    //================================================================================ [공통 기능] 비밀번호 수정 (before_user_pw, after_user_pw, user_account, update_by 받아야함 (이론적으로 update_by, user_account가 동일할 것 (mypage이기 때문)
    app.put('/changepwself',loginCheck,async function(req,res){
      let currentPwRow = await strFunc("SELECT user_pw FROM tb_groupware_user where user_account = '" + req.body.user_account + "'")
      .then((rowResult)=>{return {success:true, result:rowResult}})
      .catch((err)=>{return {success:false, result:err}})

      if(currentPwRow.result.length=1){
        if(bcrypt.compareSync(req.body.before_user_pw, currentPwRow.result[0].user_pw)){

          let hasedPw = await bcryptHashing(req.body.after_user_pw)

          let setArrys=[]
          setArrys.push("user_pw='"+hasedPw+"'")
          setArrys.push("update_datetime=now()")

          let qryResult = await strFunc("UPDATE tb_groupware_user SET "+ setArrys.join(",") + " where user_account = '" + req.body.user_account + "'")
          .then(async (rowResult)=>{
            return {success:true, result:rowResult}
          })
          .catch((err)=>{return {success:false, result:err}})

          if(qryResult.success){
            let auditTrailRows=[]
            auditTrailRows.push(req.body.update_by,"'내 계정정보'에서 자신의 계정 '" + req.body.user_account + "'의 비밀번호 수정",req.body.user_account)
            await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
          }

          res.json(qryResult)
        }
        else{
          res.json({success:false, result:"현재 패스워드가 일치하지 않습니다."})
        }      
      }
      else{
        res.json({success:false, result:"유일한 계정이 확인되지 않습니다."})
      }
    })

    async function bcryptHashing(plainPW){
      let hashedPw = await bcrypt.hash(plainPW, saltRounds)
      return hashedPw
    }

  //================================================================================ [공통 기능] 계정 부여된 권한 조회 (tb_user_auth에서 사용할 PK값 중 user_account 전달이 필요함) [Audit Trail 제외]
  app.get('/getgroupwareuser', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_groupware_user " + await whereClause("tb_groupware_user",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  });

  //================================================================================ [공통 기능] 전자서명 (현재 사용자 & 패스워드만 확인해줌) [Audit Trail 제외]
  app.get('/signpw', loginCheck, async function (req, res) {
    let user_account=req.query.user_account
    let user_pw =req.query.user_pw
    let qryResult = await strFunc("SELECT user_pw FROM tb_groupware_user where user_account = '" + req.query.user_account + "'")
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    if(qryResult.result.length=1){
      if(bcrypt.compareSync(req.query.user_pw, qryResult.result[0].user_pw)){
        res.json({signStat:true, msg:"사용자인증 되었습니다."})
      }
      else{
        res.json({signStat:false, msg:"패스워드가 일치하지 않습니다."})
      }      
    }
    else{
      res.json({signStat:false, msg:"유일한 계정이 확인되지 않습니다."})
    }
});

  //================================================================================ Table의 UUID 값 때문인지  "TypeError: Do not know how to serialize a BigInt" 방지용
  BigInt.prototype.toJSON = function() {       
    return this.toString()
  }

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/postextdatatmms', loginCheck, async function(req,res){
    let columNamesArr=['data_order', 'eq_team', 'eq_part', 'eq_location', 
    'drug_form', 'room_no', 'eq_code_alt', 'eq_code', 'eq_name', 'eq_grade', 'eq_inst_date', 'eq_capa', 'eq_model', 'eq_serial', 
    'eq_manf', 'eq_vendor', 'eq_is_legal', 'manuf_country', 'used_util', 'eq_cat', 'rev_status', 'is_latest', 'data_rev', 'eq_status',
    'insert_by', 'insert_datetime','update_by', 'update_datetime', 'uuid_binary']
    let questions=['?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?','?',"'"+req.body.handle_by+"'",'now()','NULL','NULL','UUID_TO_BIN(UUID())']
    let valueArrys=[]
    let dupStrArry=['data_order=VALUES(data_order)','eq_team=VALUES(eq_team)','eq_part=VALUES(eq_part)','eq_location=VALUES(eq_location)','drug_form=VALUES(drug_form)','room_no=VALUES(room_no)',
    'eq_code_alt=VALUES(eq_code_alt)','eq_name=VALUES(eq_name)','eq_grade=VALUES(eq_grade)','eq_inst_date=VALUES(eq_inst_date)','eq_capa=VALUES(eq_capa)','eq_model=VALUES(eq_model)','eq_serial=VALUES(eq_serial)',
    'eq_manf=VALUES(eq_manf)','eq_vendor=VALUES(eq_vendor)','eq_is_legal=VALUES(eq_is_legal)','manuf_country=VALUES(manuf_country)','used_util=VALUES(used_util)', 
    'eq_cat=VALUES(eq_cat)','rev_status=VALUES(rev_status)','is_latest=VALUES(is_latest)','data_rev=VALUES(data_rev)','eq_status=VALUES(eq_status)',"update_by='"+req.body.handle_by+"'",'update_datetime=now()']

    req.body.extdatas.map((oneRow,i)=>{
      let oneValueArry=[]
      Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
        oneValueArry.push(req.body.extdatas[i][keyName])
      })
      valueArrys.push(oneValueArry)
    })


    let auditTrailRows=[]


    let qryResult = await batchInsertOnDupliFunc("tb_extdata_tmms_whole_asset",columNamesArr,questions,valueArrys,dupStrArry)
    .then(async (rowResult)=>{
      auditTrailRows.push(req.body.handle_by,"'" + "외부 시스템 데이터 업로드 기능을 이용하여 'TMMS DATA(설비) (FROM: 설비자산>전체마스터)' 데이터 업데이트", "'TMMS DATA(설비) (FROM: 설비자산>전체마스터)' 외부 데이터")
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
      return {success:true, result:rowResult}
    })
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getextdatatmmswholeasset', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT data_order, eq_team, eq_part, eq_location, drug_form, room_no, eq_code_alt, eq_code, eq_name, eq_grade, eq_inst_date, eq_capa, eq_model, eq_serial, eq_manf, eq_vendor, eq_is_legal, manuf_country, used_util, eq_cat, rev_status, is_latest, data_rev, eq_status, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by,insert_datetime, update_by, update_datetime FROM tb_extdata_tmms_whole_asset " + await whereClause("tb_extdata_tmms_whole_asset",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
});

//================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
app.post('/postextdatasapzmmr1010', loginCheck, async function(req,res){
  let columNamesArr=['mat_cat', 'plant_code', 'mat_code', 'mat_name', 'mat_unit', 'mat_unit_name', 'mat_code_alt1', 'mat_code_alt2', 'mat_code_alt3',
  'mat_code_alt4', 'mat_code_alt5', 'mat_code_alt6', 'mat_unit_alt1', 'mat_unit_alt1_name', 'mat_unit_alt1_value', 'mat_group', 'mat_ext_group',
  'status_plants', 'status_mats_plants', 'max_store_level', 'prod_cat', 'prod_scrap', 'mrp_group', 'buy_group', 'mrp_cat', 'reorder_point', 'mrp_manager', 
  'lot_size', 'lot_min_size', 'lot_max_size', 'lot_fix', 'assemble_group', 'provide_specical', 'provide_cat', 'production_store_location', 
  'use_quater', 'ep_store_location', 'internal_production', 'intend_prodvide', 'leadtime_import', 'safe_time_indicator', 'safe_time', 'production_director', 
  'delivery_tolerance_below', 'delivery_tolerance_above', 'temp_condition', 'mat_group_pack_mat', 'store_condition', 'remained_effect', 'total_shelf_life', 
  'check_setting', 'provide_specical_cat', 'vendor_list', 'auto_po', 'lab_design_room', 'prod_layer_skeleton', 'layer1_name', 'layer2_name', 'layer3_name', 
  'layer4_name', 'round_value', 'plant_delete', 'whole_delete', 'record_datetime', 'lastest_datetime', 'record_cat', 'std_text', 'std_code', 'std_code_name', 
  'rep_code', 'std_code_alt1', 'insurance_code', 'approval_cat', 'approval_cat_name', 'approval_name', 'evaluation_class', 'pack_unit_authority', 'pack_unit_prod_code', 
  'mat_account_group', 'safe_stock', 'min_safe_stock', 'provided_plant', 'uuid_binary', 'insert_by', 'insert_datetime', 'update_by', 'update_datetime']
  let questions=['?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  '?', '?',  '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?',
  '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', 
  'UUID_TO_BIN(UUID())', "'"+req.body.handle_by+"'", 'now()', 'NULL', 'NULL']
  let valueArrys=[]
  let dupStrArry=[
    'mat_cat= VALUES(mat_cat)', 'plant_code= VALUES(plant_code)', 'mat_code= VALUES(mat_code)', 'mat_name= VALUES(mat_name)', 'mat_unit= VALUES(mat_unit)',
    'mat_unit_name= VALUES(mat_unit_name)', 'mat_code_alt1= VALUES(mat_code_alt1)', 'mat_code_alt2= VALUES(mat_code_alt2)', 'mat_code_alt3= VALUES(mat_code_alt3)',
    'mat_code_alt4= VALUES(mat_code_alt4)', 'mat_code_alt5= VALUES(mat_code_alt5)', 'mat_code_alt6= VALUES(mat_code_alt6)', 'mat_unit_alt1= VALUES(mat_unit_alt1)',
    'mat_unit_alt1_name= VALUES(mat_unit_alt1_name)', 'mat_unit_alt1_value= VALUES(mat_unit_alt1_value)', 'mat_group= VALUES(mat_group)', 'mat_ext_group= VALUES(mat_ext_group)',
    'status_plants= VALUES(status_plants)', 'status_mats_plants= VALUES(status_mats_plants)', 'max_store_level= VALUES(max_store_level)', 'prod_cat= VALUES(prod_cat)',
    'prod_scrap= VALUES(prod_scrap)', 'mrp_group= VALUES(mrp_group)', 'buy_group= VALUES(buy_group)', 'mrp_cat= VALUES(mrp_cat)', 'reorder_point= VALUES(reorder_point)',
    'mrp_manager= VALUES(mrp_manager)', 'lot_size= VALUES(lot_size)', 'lot_min_size= VALUES(lot_min_size)', 'lot_max_size= VALUES(lot_max_size)', 'lot_fix= VALUES(lot_fix)',
    'assemble_group= VALUES(assemble_group)', 'provide_specical= VALUES(provide_specical)', 'provide_cat= VALUES(provide_cat)', 'production_store_location= VALUES(production_store_location)',
    'use_quater= VALUES(use_quater)', 'ep_store_location= VALUES(ep_store_location)', 'internal_production= VALUES(internal_production)', 'intend_prodvide= VALUES(intend_prodvide)',
    'leadtime_import= VALUES(leadtime_import)', 'safe_time_indicator= VALUES(safe_time_indicator)', 'safe_time= VALUES(safe_time)', 'production_director= VALUES(production_director)',
    'delivery_tolerance_below= VALUES(delivery_tolerance_below)', 'delivery_tolerance_above= VALUES(delivery_tolerance_above)', 'temp_condition= VALUES(temp_condition)',
    'mat_group_pack_mat= VALUES(mat_group_pack_mat)', 'store_condition= VALUES(store_condition)', 'remained_effect= VALUES(remained_effect)', 'total_shelf_life= VALUES(total_shelf_life)',
    'check_setting= VALUES(check_setting)', 'provide_specical_cat= VALUES(provide_specical_cat)', 'vendor_list= VALUES(vendor_list)', 'auto_po= VALUES(auto_po)', 'lab_design_room= VALUES(lab_design_room)',
    'prod_layer_skeleton= VALUES(prod_layer_skeleton)', 'layer1_name= VALUES(layer1_name)', 'layer2_name= VALUES(layer2_name)', 'layer3_name= VALUES(layer3_name)', 'layer4_name= VALUES(layer4_name)',
    'round_value= VALUES(round_value)', 'plant_delete= VALUES(plant_delete)', 'whole_delete= VALUES(whole_delete)', 'record_datetime= VALUES(record_datetime)', 'lastest_datetime= VALUES(lastest_datetime)',
    'record_cat= VALUES(record_cat)', 'std_text= VALUES(std_text)', 'std_code= VALUES(std_code)', 'std_code_name= VALUES(std_code_name)', 'rep_code= VALUES(rep_code)', 'std_code_alt1= VALUES(std_code_alt1)',
    'insurance_code= VALUES(insurance_code)', 'approval_cat= VALUES(approval_cat)', 'approval_cat_name= VALUES(approval_cat_name)', 'approval_name= VALUES(approval_name)', 'evaluation_class= VALUES(evaluation_class)',
    'pack_unit_authority= VALUES(pack_unit_authority)', 'pack_unit_prod_code= VALUES(pack_unit_prod_code)', 'mat_account_group= VALUES(mat_account_group)', 'safe_stock= VALUES(safe_stock)', 'min_safe_stock= VALUES(min_safe_stock)',
    'provided_plant= VALUES(provided_plant)',"update_by='"+req.body.handle_by+"'",'update_datetime=now()'
  ]

  req.body.extdatas.map((oneRow,i)=>{
    let oneValueArry=[]
    Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
      oneValueArry.push(req.body.extdatas[i][keyName])
    })
    valueArrys.push(oneValueArry)
  })

  let auditTrailRows=[]

  let qryResult = await batchInsertOnDupliFunc("tb_extdata_sapzmmrten",columNamesArr,questions,valueArrys,dupStrArry)
  .then(async (rowResult)=>{
    auditTrailRows.push(req.body.handle_by,"'" + "외부 시스템 데이터 업로드 기능을 이용하여 'SAP DATA (REPORT FORM : ZMMR1010)' 데이터 업데이트", "'SAP DATA (REPORT FORM : ZMMR1010)' 외부 데이터")
    await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
    return {success:true, result:rowResult}})
  .catch((err)=>{return {success:false, result:err}})
  res.json(qryResult)
})
//================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
app.post('/postextdataeqmsatemplate', loginCheck, async function(req,res){
  let columNamesArr=['pr_no', 'create_datetime', 'project', 'pr_title', 'written_by', 'due_date', 'pr_state', 'date_closed', 
  'uuid_binary', 'insert_by', 'insert_datetime', 'update_by', 'update_datetime', ]
  let questions=['?', '?', '?', '?', '?', '?', '?', '?', 'UUID_TO_BIN(UUID())', "'"+req.body.handle_by+"'", 'now()', 'NULL', 'NULL']
  let valueArrys=[]
  let dupStrArry=['pr_no= VALUES(pr_no)', 'create_datetime= VALUES(create_datetime)', 'project= VALUES(project)', 'pr_title= VALUES(pr_title)',
  'written_by= VALUES(written_by)', 'due_date= VALUES(due_date)', 'pr_state= VALUES(pr_state)', 'date_closed= VALUES(date_closed)',
  "update_by='"+req.body.handle_by+"'", 'update_datetime=now()']

  req.body.extdatas.map((oneRow,i)=>{
    let oneValueArry=[]
    Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
      oneValueArry.push(req.body.extdatas[i][keyName])
    })
    if (oneValueArry.length==8) valueArrys.push(oneValueArry)
    else console.log(oneValueArry)
  })

  let auditTrailRows=[]

  let qryResult = await batchInsertOnDupliFunc("tb_extdata_eqms_a_template",columNamesArr,questions,valueArrys,dupStrArry)
  .then(async (rowResult)=>{
    auditTrailRows.push(req.body.handle_by,"'" + "외부 시스템 데이터 업로드 기능을 이용하여 'EQMS DATA (TEMPLATE : A:공통)' 데이터 업데이트", "'EQMS DATA (TEMPLATE : A:공통)' 외부 데이터")
    await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
    return {success:true, result:rowResult}})
  .catch((err)=>{return {success:false, result:err}})
  res.json(qryResult)
})

  //================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
  app.post('/postextdatatmmslocation', loginCheck, async function(req,res){
    let columNamesArr=[ 'order_no', 'location_name', 'costcenter', 'location_code', 'location_l', 'location_order_value', 'location_status',
    'uuid_binary', 'insert_by', 'insert_datetime', 'update_by', 'update_datetime',]
    let questions=['?', '?', '?', '?', '?', '?', '?', 'UUID_TO_BIN(UUID())', "'"+req.body.handle_by+"'", 'now()', 'NULL', 'NULL']
    let valueArrys=[]
    let dupStrArry=[ 'order_no= VALUES(order_no)', 'location_name= VALUES(location_name)', 'costcenter= VALUES(costcenter)',
    'location_code= VALUES(location_code)', 'location_l= VALUES(location_l)', 'location_order_value= VALUES(location_order_value)',
    'location_status= VALUES(location_status)',
    "update_by='"+req.body.handle_by+"'", 'update_datetime=now()']

    req.body.extdatas.map((oneRow,i)=>{
      let oneValueArry=[]
      Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
        oneValueArry.push(req.body.extdatas[i][keyName])
      })
      valueArrys.push(oneValueArry)
    })

    let auditTrailRows=[]

    let qryResult = await batchInsertOnDupliFunc("tb_extdata_tmms_location",columNamesArr,questions,valueArrys,dupStrArry)
    .then(async (rowResult)=>{
      auditTrailRows.push(req.body.handle_by,"'" + "외부 시스템 데이터 업로드 기능을 이용하여 'TMMS DATA (설비위치) (FROM : 설비자산>설비위치)' 데이터 업데이트", "'TMMS DATA (설비위치) (FROM : 설비자산>설비위치)' 외부 데이터")
      await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
      return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
  })

//================================================================================ [공통 기능] 계정 중복생성 확인 [Audit Trail 제외]
app.post('/postextdatagroupwareaccount', loginCheck, async function(req,res){
  let columNamesArr=['user_account', 'user_pw', 'user_name', 'user_position', 'user_team', 'user_company', 'user_email', 'user_phone', 'user_auth',	'account_status', 'uuid_binary', 'insert_by', 'insert_datetime', 'update_by', 'update_datetime'] 
  let questions=['?', '?', '?', '?', '?', '?', '?', '?', '?', '?', 'UUID_TO_BIN(UUID())', "'"+req.body.handle_by+"'", 'now()', 'NULL', 'NULL']
  let valueArrys=[]
  let dupStrArry=['user_name=VALUES(user_name)', 'user_position=VALUES(user_position)', 
  'user_team=VALUES(user_team)', 'user_company=VALUES(user_company)', 'user_email=VALUES(user_email)', 'user_phone=VALUES(user_phone)', "update_by='"+req.body.handle_by+"'", 'update_datetime=now()']

  req.body.extdatas.map((oneRow,i)=>{
    let oneValueArry=[]
    Object.keys(req.body.extdatas[i]).map(async (keyName,j)=>{
      oneValueArry.push(req.body.extdatas[i][keyName])
    })
    valueArrys.push(oneValueArry)
  })

  let auditTrailRows=[]

  let qryResult = await batchInsertOnDupliFunc("tb_groupware_user",columNamesArr,questions,valueArrys,dupStrArry)
  .then(async (rowResult)=>{
    auditTrailRows.push(req.body.handle_by,"'" + "외부 시스템 데이터 업로드 기능을 이용하여 '베어월드 계정' 데이터 업데이트", "'베어월드 계정' 외부 데이터")
    await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)
    return {success:true, result:rowResult}})
  .catch((err)=>{return {success:false, result:err}})
  res.json(qryResult)
})
  //================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
  app.get('/getmnguser', loginCheck, async function (req, res) {
    let qryResult = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, user_auth, account_status, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary, insert_by, insert_datetime, update_by, update_datetime FROM tb_groupware_user " + await whereClause("tb_groupware_user",req.query.searchKeyWord))
    .then((rowResult)=>{return {success:true, result:rowResult}})
    .catch((err)=>{return {success:false, result:err}})
    res.json(qryResult)
});
 //================================================================================ [문서 기능] 문서 정보 수정
 app.put('/putedituserinfo',loginCheck,async function(req,res){

  let tartgetRowSelectStr= "SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, user_auth, account_status, remark  FROM tb_groupware_user WHERE user_account = '" + req.body.user_account +"'"

  let auditTrailDataBefore= await strFunc(tartgetRowSelectStr)
  let auditTrailDataAfter=[]
  let auditTrailRows=[]

  let setArrys=[]

  setArrys.push("remark='"+req.body.remark+"'")
  setArrys.push("user_auth='"+req.body.user_auth+"'")
  setArrys.push("account_status='"+req.body.account_status+"'")
  setArrys.push("update_by='"+req.body.update_by+"'")
  setArrys.push("update_datetime=now()")

  let qryResult = await strFunc("UPDATE tb_groupware_user SET "+ setArrys.join(",") + " WHERE user_account = '" + req.body.user_account +"'")
  .then(async (rowResult)=>{
    auditTrailDataAfter = await strFunc(tartgetRowSelectStr)
    
    auditTrailRows.push(req.body.update_by,"계정 '" + req.body.user_account + "' 의 정보 수정", JSON.stringify({Before:auditTrailDataBefore,After:auditTrailDataAfter}))
    await batchInsertFunc('tb_audit_trail',['user_account', 'user_action', 'data', 'action_datetime', 'uuid_binary'], ['?','?','?','now()','UUID_TO_BIN(UUID())'],auditTrailRows,false)

    return {success:true, result:rowResult}})
  .catch((err)=>{return {success:false, result:err}})
  res.json(qryResult)
})

//================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
app.get('/getmypage', loginCheck, async function (req, res) {
  let qryResult = await strFunc("SELECT user_account, user_name, user_position, user_team, user_company, user_email, user_phone, remark, BIN_TO_UUID(uuid_binary) AS uuid_binary FROM tb_groupware_user WHERE user_account ='"+req.query.user_account+"'")
  .then((rowResult)=>{
    return {success:true, result:rowResult}})
  .catch((err)=>{
    return {success:false, result:err}})
  res.json(qryResult)
});


//================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
app.get('/getqualmtstat', loginCheck, async function (req, res) {
  let qryResult = await strFunc("SELECT * FROM view_qual_status WHERE mng_team ='"+req.query.mng_team+"'")
  .then((rowResult)=>{
    return {success:true, result:rowResult}})
  .catch((err)=>{
    return {success:false, result:err}})
  res.json(qryResult)
});


//================================================================================ [공통 기능] 계정 리스트 조회 [Audit Trail 제외]
app.get('/getcsvstat', loginCheck, async function (req, res) {
  let whereClause ="WHERE "
  + "(CS_NO like '%"+req.query.searchKeyWord+"%') OR (doc_no like '%"+req.query.searchKeyWord+"%') OR (rev_no like '%"+req.query.searchKeyWord+"%') OR (doc_title like '%"+req.query.searchKeyWord+"%')"
  + " OR (approval_date like '%"+req.query.searchKeyWord+"%') OR (csAtt like '%"+req.query.searchKeyWord+"%')"
  console.log(whereClause)
  let qryResult = await strFunc("SELECT * FROM view_csv_status " + whereClause)
  .then((rowResult)=>{
    return {success:true, result:rowResult}})
  .catch((err)=>{
    return {success:false, result:err}})
  res.json(qryResult)
});

//================================================================================ [공통 기능] 모든 route를 react SPA로 연결 (이 코드는 맨 아래 있어야함)
app.get('/', function (req, res) {
  res.sendFile(path.join(__dirname, process.env.react_build_path+'index.html'));
});

app.get('*', function (req, res) {
  res.sendFile(path.join(__dirname, process.env.react_build_path+'index.html'));
});