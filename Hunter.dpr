{$R UAC.RES}
program Hunter;

uses
  windows,
  Forms,
  Unit1 in 'Unit1.pas' {Form1};

{$R *.res}

var
 hWindow: dword;

begin
  Application.Initialize;
  Application.Title:='Hunter';
  hWindow := FindWindow('TForm1', 'Hunter');
  if hWindow > 0 then
   begin
    SetForegroundWindow(hWindow);
    //ExitProcess(0);
   end;
  Application.CreateForm(TForm1, Form1);
  Application.ShowMainForm:=False;
  Application.Run;
end.
