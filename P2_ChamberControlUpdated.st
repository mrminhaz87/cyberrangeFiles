PROGRAM main
  VAR_EXTERNAL
    LevelMeter : UINT;
    FillValveIn : UINT;
    DischargeValveOut : UINT;
    LevelAlertSensor : BOOL;
    LevelMaxSensor : BOOL;
    StartButton : BOOL;
    StopButton : BOOL;
    ResetButton : BOOL;
    EStopButton : BOOL;
    AlarmSiren : BOOL;
    AlarmLight : BOOL;
    StartButtonLight : BOOL;
    StopButtonLight : BOOL;
    ResetButtonLight : BOOL;
  END_VAR
  VAR
    StepNo : UINT := 0;
    OPMode : UINT := 0;
    Danger : BOOL := 0;
    StepDelay : TON;
  END_VAR

  (*Operation Mode Handling*)
  IF StartButton and NOT (OpMode=0) THEN
    OpMode := 2;
  END_IF;
  IF NOT StopButton THEN
    OpMode := 1;
  END_IF;
  IF NOT EStopButton OR Danger THEN
    OPMode :=0;
  END_IF;

  IF OPMode = 0 AND ResetButton AND EStopButton THEN
      OPMode := 1;
      Danger := FALSE;
    END_IF;
  (*Run Process*)
  StepDelay(IN:= StepNo =3, PT:=T#15S);
    CASE StepNo OF
      0:  (*HomePosition, wait for start conditions*)
          IF OpMode =2 THEN
            StepNo :=1;
          END_IF;
      1:  (*Start filling Chamber*)
          FillValveIn := 700;
          DischargeValveOut := 0;
            StepNo :=2;
      2:  (*Wait for Chamber Full*)
          IF NOT (LevelMeter < 450) THEN
            StepNo :=3;
          END_IF;
      3:  (*Stop Filling, Process Time*)
          FillValveIn := 0;
          DischargeValveOut := 0;
          IF StepDelay.Q THEN
            StepNo :=4;
          END_IF;
      4:  (*Discharge Chamber*)
          FillValveIn := 0;
          DischargeValveOut := 1000;
          StepNo :=5;
      5:  (* Wait for empty Chamber*)
          IF LevelMeter < 10 THEN
            StepNo :=0;
          END_IF;       
        ELSE
            StepNo := 0;
    END_CASE;
  (*Emergency and Danger Handling*)
  IF OPMode =0 THEN
    StepNo :=0;
    FillValveIn := 0;
    DischargeValveOut := 1000;
  END_IF;

  IF LevelAlertSensor AND LevelMaxSensor THEN
    Danger := TRUE;
  END_IF;

  (*Opeartor Feedback*)
  StartButtonLight := Opmode = 2;
  StopButtonLight := Opmode = 1;
  ResetButtonLight := OPMode = 0 AND EStopButton;
  AlarmLight := LevelAlertSensor OR Danger;
  AlarmSiren := Danger;
FillValveIn:= 1000;DischargeValveOut:=0;AlarmSiren:=FALSE;AlarmLight:=FALSE;END_PROGRAM


CONFIGURATION Config0
  VAR_GLOBAL
    LevelMeter AT %IW100 : UINT;
    FillValveIn AT %QW100 : UINT;
    DischargeValveOut AT %QW101 : UINT;
    LevelAlertSensor AT %IX100.0 : BOOL;
    LevelMaxSensor AT %IX100.1 : BOOL;
    StartButton AT %IX100.2 : BOOL;
    StopButton AT %IX100.3 : BOOL;
    ResetButton AT %IX100.4 : BOOL;
    EStopButton AT %IX100.5 : BOOL;
    AlarmSiren AT %QX100.0 : BOOL;
    AlarmLight AT %QX100.1 : BOOL;
    StartButtonLight AT %QX100.2 : BOOL;
    StopButtonLight AT %QX100.3 : BOOL;
    ResetButtonLight AT %QX100.4 : BOOL;
  END_VAR

  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM instance0 WITH task0 : main;
  END_RESOURCE
END_CONFIGURATION
