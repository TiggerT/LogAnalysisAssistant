@echo off
setlocal enabledelayedexpansion
echo �����룺system(��ϵͳ��־)/security(����ȫ��־)/��־�ļ�����·��
echo 	PS: ֱ�ӻس���Ĭ�ϲ�ѯ��ȫsecurity��־
set /p "logfile=" || set "logfile=Security"
:display_menu
cls
echo �X�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�[
echo �U   Winodows��־��������V1.0 by_Loki.T      �U
echo �U               ��ѡ��(^^_^^)��               �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 0. �Զ����ѯ                             �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 1. �Զ����ѯ�������������ļ�output.cvs �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 2. �鿴�����¼�ɹ����û�����IP           �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 3. �鿴�����¼ʧ�ܵ��û�����IP           �U 
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 4. RDPԶ�̳ɹ���¼�ļ�¼                  �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 5. ϵͳ��ʷ���ػ���¼                     �U
echo �U(PS:�Ӳ����������־����һ��ļ�¼��̫׼ȷ)�U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 6. �ض�ʱ�䷶Χ�ڵ�¼�ɹ����¼�           �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 7. ������ɾ���û��¼�                     �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 8. Ȩ��ά�֣��޸�֪ӳ��ٳ��¼�           �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 9. �����ƶ�������KerberosƱ������¼�     �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 10. �ۼ��������־������¼�(ϵͳ��־)    �U
echo �d�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�g
echo �U 11. �򹥷���NTDS�ļ�������HashDumpȡ֤    �U
echo �^�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�T�a

set /p choice=��ѡ��Ҫִ�е�����: 
if "!choice!"=="0" (
	set /p choice1=�Ƿ���Ҫ�޶�ʱ�䷶Χ������yes/no:
	if "!choice1!"=="yes" (
		set /p starttime=��������ʼʱ�� ���� 2024-01-01 18:00:00:
		set /p endtime=���������ʱ�� ���� 2024-01-01 18:00:00:
		set /p id=������Ҫ��ѯ���¼�ID:
		call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where TimeGenerated>'!starttime!' and TimeGenerated<'!endtime!' and Eventid=!id!"
		goto display_menu
	)else if "!choice1!"=="no" (
		set /p id=������Ҫ��ѯ���¼�ID:
		call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=!id!" 
		goto display_menu
	)else (
	echo ��Ч��ѡ��
    goto display_menu
	)
)else if "!choice!"=="1" (
	set /p choice1=�Ƿ���Ҫ�޶�ʱ�䷶Χ������yes/no:
	if "!choice1!"=="yes" (
		set /p starttime=��������ʼʱ�� ���� 2024-01-01 18:00:00:
		set /p endtime=���������ʱ�� ���� 2024-01-01 18:00:00:
		set /p id=������Ҫ��ѯ���¼�ID:
		call LogParser.exe -i:evt -o:CSV "select * from !logfile! where Eventid='!id!' and TimeGenerated>'!starttime!' and TimeGenerated<'!endtime!'" > outcome.csv
		goto display_menu
	)else if "!choice1!"=="no" (
		set /p id=������Ҫ��ѯ���¼�ID:
		call LogParser.exe -i:evt -o:CSV "select * from !logfile! where Eventid=!id!" > outcome.csv
		goto display_menu
	)else (
	echo ��Ч��ѡ��
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
	set /p starttime=��������ʼʱ�� ���� 2024-01-01 18:00:00:
	set /p endtime=���������ʱ�� ���� 2024-01-01 18:00:00:
    call LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as UserName,EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName,EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM !logfile! where TimeGenerated>'!starttime!' and TimeGenerated<'!endtime!' and EventID=4624"
    goto display_menu
)else if "!choice!"=="7" (
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=4720 or Eventid=4726"
    goto display_menu
)else if "!choice!"=="8" (
	REM �����޸�֪ӳ��ٳֻ�����3000��3001����־
	REM �ɲο���https://cloud.tencent.com/developer/article/2130123
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=3000 or Eventid=3001"
    goto display_menu
)else if "!choice!"=="9" (
	REM  4768Ϊ����Kerberos�����֤Ʊ�ݣ�TGT����4769Ϊ����Kerberos����Ʊ��
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=4768 or Eventid=4769"
    goto display_menu
)else if "!choice!"=="10" (
	REM ������ʹ�ù������Windows��־����������104��1102��ϵͳ��־
	REM �ɲο���https://cloud.tencent.com/developer/article/2200016?areaSource=102001.19&traceId=-pdOnHfVQJYFYtrcCXEt9
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=1102 or Eventid=104"
    goto display_menu
)else if "!choice!"=="11" (
	REM ��ȡ���߽���NTDS�ļ����ܷ�ʽ��ȡ���û�Hashʱ���ܿ��ܻᴥ��4799ö�ٱ��ذ�ȫ���¼��������Ų��¼���������ȡ֤��
	REM �ɲο���https://blog.csdn.net/yy17111342926/article/details/132480077
	call LogParser.exe -i:evt -o:DATAGRID "select * from !logfile! where Eventid=4799"
    goto display_menu
)else (
    echo ��Ч��ѡ��
    goto display_menu
)


