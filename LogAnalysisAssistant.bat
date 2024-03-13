@echo off
setlocal enabledelayedexpansion
echo 请输入：system(即系统日志)/security(即安全日志)/日志文件完整路径
echo 	PS: 直接回车即默认查询安全security日志
set /p "logfile=" || set "logfile=Security"
:display_menu
cls
echo ╔═══════════════════════════════════════════╗
echo ║   Winodows日志分析助手V1.0 by_Loki.T      ║
echo ║               请选择(^^_^^)：               ║
echo ╠═══════════════════════════════════════════╣
echo ║ 0. 自定义查询                             ║
echo ╠═══════════════════════════════════════════╣
echo ║ 1. 自定义查询并将结果输出到文件output.cvs ║
echo ╠═══════════════════════════════════════════╣
echo ║ 2. 查看最近登录成功的用户名和IP           ║
echo ╠═══════════════════════════════════════════╣
echo ║ 3. 查看最近登录失败的用户名和IP           ║ 
echo ╠═══════════════════════════════════════════╣
echo ║ 4. RDP远程成功登录的记录                  ║
echo ╠═══════════════════════════════════════════╣
echo ║ 5. 系统历史开关机记录                     ║
echo ║(PS:从测试情况看日志对这一块的记录不太准确)║
echo ╠═══════════════════════════════════════════╣
echo ║ 6. 特定时间范围内登录成功的事件           ║
echo ╠═══════════════════════════════════════════╣
echo ║ 7. 创建或删除用户事件                     ║
echo ╠═══════════════════════════════════════════╣
echo ║ 8. 权限维持：无感知映像劫持事件           ║
echo ╠═══════════════════════════════════════════╣
echo ║ 9. 横向移动：请求Kerberos票据相关事件     ║
echo ╠═══════════════════════════════════════════╣
echo ║ 10. 痕迹清除：日志被清除事件(系统日志)    ║
echo ╠═══════════════════════════════════════════╣
echo ║ 11. 域攻防：NTDS文件解密类HashDump取证    ║
echo ╚═══════════════════════════════════════════╝

set /p choice=请选择要执行的命令: 
if "!choice!"=="0" (
	set /p choice1=是否需要限定时间范围？输入yes/no:
	if "!choice1!"=="yes" (
		set /p starttime=请输入起始时间 例如 2024-01-01 18:00:00:
		set /p endtime=请输入结束时间 例如 2024-01-01 18:00:00:
		set /p id=请输入要查询的事件ID:
		call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where TimeGenerated>'!starttime!' and TimeGenerated<'!endtime!' and Eventid=!id!"
		goto display_menu
	)else if "!choice1!"=="no" (
		set /p id=请输入要查询的事件ID:
		call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=!id!" 
		goto display_menu
	)else (
	echo 无效的选择
    goto display_menu
	)
)else if "!choice!"=="1" (
	set /p choice1=是否需要限定时间范围？输入yes/no:
	if "!choice1!"=="yes" (
		set /p starttime=请输入起始时间 例如 2024-01-01 18:00:00:
		set /p endtime=请输入结束时间 例如 2024-01-01 18:00:00:
		set /p id=请输入要查询的事件ID:
		call LogParser.exe -i:evt -o:CSV "select * from !logfile! where Eventid='!id!' and TimeGenerated>'!starttime!' and TimeGenerated<'!endtime!'" > outcome.csv
		goto display_menu
	)else if "!choice1!"=="no" (
		set /p id=请输入要查询的事件ID:
		call LogParser.exe -i:evt -o:CSV "select * from !logfile! where Eventid=!id!" > outcome.csv
		goto display_menu
	)else (
	echo 无效的选择
    goto display_menu
	)
)else if "!choice!"=="2" (
    call LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as UserName,EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName,EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM !logfile! where EventID=4624 ORDER BY LoginTime DESC"
    goto display_menu
)else if "!choice!"=="3" (
	 call LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as Username,EXTRACT_TOKEN(Message,39,' ') as Loginip FROM !logfile! where EventID=4625 ORDER BY LoginTime DESC"
    goto display_menu
)else if "!choice!"=="4" (
    call LogParser.exe "SELECT TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as UserName,EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName,EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM Security WHERE EventID = 4624 AND EXTRACT_TOKEN(Strings,8,'|') = '10'" -i:EVT -o:DATAGRID
    goto display_menu
)else if "!choice!"=="5" (
    call LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated, EventID, Message FROM System WHERE EventID = 6005 OR EventID = 6006"
    goto display_menu
)else if "!choice!"=="6" (
	set /p starttime=请输入起始时间 例如 2024-01-01 18:00:00:
	set /p endtime=请输入结束时间 例如 2024-01-01 18:00:00:
    call LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as UserName,EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName,EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM !logfile! where TimeGenerated>'!starttime!' and TimeGenerated<'!endtime!' and EventID=4624"
    goto display_menu
)else if "!choice!"=="7" (
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=4720 or Eventid=4726"
    goto display_menu
)else if "!choice!"=="8" (
	REM 进行无感知映像劫持会留下3000或3001的日志
	REM 可参考：https://cloud.tencent.com/developer/article/2130123
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=3000 or Eventid=3001"
    goto display_menu
)else if "!choice!"=="9" (
	REM  4768为请求Kerberos身份验证票据（TGT），4769为请求Kerberos服务票据
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=4768 or Eventid=4769"
    goto display_menu
)else if "!choice!"=="10" (
	REM 攻击者使用工具清除Windows日志往往会留下104和1102的系统日志
	REM 可参考：https://cloud.tencent.com/developer/article/2200016?areaSource=102001.19&traceId=-pdOnHfVQJYFYtrcCXEt9
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=1102 or Eventid=104"
    goto display_menu
)else if "!choice!"=="11" (
	REM 采取工具进行NTDS文件解密方式窃取域用户Hash时，很可能会触发4799枚举本地安全组事件，可以排查事件辅助进行取证。
	REM 可参考：https://blog.csdn.net/yy17111342926/article/details/132480077
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=4799"
    goto display_menu
)else (
    echo 无效的选择
    goto display_menu
)


