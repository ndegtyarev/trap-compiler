#!/usr/bin/perl

=comment

== MIB Compiler to SMARTS TRAP v.5.5.6
== Author Nick Degtyarev
== trap-compiler.pl
== USAGE: perl trap-compiler.pl

=cut

use v5.10.1;
use strict;
use warnings;
use utf8;
use FindBin;
use FileHandle;
use Data::Dumper;
use POSIX qw(strftime);
open(STDERR, '>:encoding(UTF-8)', "/tmp/trap-compiler-stderr.log"); # Вывод сообщений компилятора в отдельный файл
binmode(STDERR,':utf8');
binmode(STDOUT,':utf8');
my $scrpath = "$FindBin::RealBin"; # Путь до скрипта (Не трогать, используется разными функциями)


####################[ Настройки пользовательских переменных ]####################################

# Директории списком для поиска MIB-файлов
my @MibsDirMain = ("."); # Слэш в конце не нужен
my @MibsDirLibs = ("/usr/share/snmp/mibs"); # Слэш в конце не нужен
my $logspath = "."; # Директория хранения файлов логирования
my $trapmgrfile = "./trap_mgr.conf"; # Путь до результирующего файла
my $critmain = 1; # Остановка выполения из-за дубля при обработки основной директории (1 - On, 0 - Off)
my $critlibs = 0; # Остановка выполения из-за дубля при обработки второстепенной директории (1 - On, 0 - Off)
my $dbglvl = 2; # Debug Level: 0 - Off, 1 - Low, 2 - Normal, 3 - High, 4 - Full
my $stdsection = 0; # By default do not print the DEFAULTS section of trap_mgr.conf
my $generictype = 6; # We are only handling Specific Traps (6) right now
my $experation = 3600; # Set the Experation time

####################[ Конец настроек (Далее код не менять) ]#####################################



# GLOBAL Root MIBs Definitiions
my %OIDS = ();
$OIDS{'iso'} = '.1';
$OIDS{'org'} = '.1.3';
$OIDS{'dod'} = '.1.3.6';
$OIDS{'internet'} = '.1.3.6.1';
$OIDS{'directory'} = '.1.3.6.1.1';
$OIDS{'mgmt'} = '.1.3.6.1.2';
$OIDS{'experimental'} = '.1.3.6.1.3';
$OIDS{'private'} = '.1.3.6.1.4';
$OIDS{'enterprises'} = '.1.3.6.1.4.1';
$OIDS{'mib-2'} = '.1.3.6.1.2.1';
$OIDS{'snmp'} = '.1.3.6.1.6.3.1.1';
$OIDS{'host'} = '.1.3.6.1.2.1.25';

our %already_parsed = ();
our %MibFilesMain = ();
our %MibFilesLibs = ();
our %TrapMgr = ();
our %TRAPS = ();
our %MDF = ();
our $MibType = "";
our $ModName = "";
our $TrapName = "";
our $Ent = "";
our @VarBinds = ();
our $Descr = "";
our $TrapOID = "";
our $TrapNumber = "";
our @LINE = ();
our $mdfState = 0;
our $lineCtr = 0;
our $Severity = 0;
our $logfile;
our $loguid = &genuid;


# Создаём файл логирования операций
if ($dbglvl) {
  if($logspath){
    my $ts = &timestamp;
    $logspath = $logspath."/"."trap-compiler-".$ts."-".$loguid.".log";
    if (open($logfile, '>:encoding(UTF-8)', $logspath)) {
      binmode($logfile, ":utf8");
      print $logfile "$ts Debug file begin\n";
      print "Debug is on '$logspath'\n\n";
    } else {
      print "Critical! Не удаётся открыть файл '$logspath' на запись: $!\n";
      exit(1);
    };
  };
};

# I - Загружаем все MIB-файлы из директорий в список для обработки
%MibFilesMain = &loadmibs($critmain, @MibsDirMain);
if ($dbglvl) { &wrlog('INFO Загрузка в список %MibFilesMain директорий из раздела "MIB-файлов для обработки" завершена'); };

# II - Загружаем все MIB-файлы из директорий в список для библиотеки подгрузки
%MibFilesLibs = &loadmibs($critlibs, @MibsDirLibs);
if ($dbglvl) { &wrlog('INFO Загрузка в список %MibFilesLibs директорий из раздела "Библиотеки стандартных MIB-файлов" завершена'); };

# III - Загружаем все OID'ы из MIB-файлов текущих директорий в хэш %OIDS
foreach my $key (keys %MibFilesMain) {
  if(exists($MibFilesMain{$key})){
    if ($dbglvl) { &wrlog("INFO MIB-файл отправлен на импорт parse_file('$MibFilesMain{$key}', '$key')"); };
    parse_file($MibFilesMain{$key}, $key);
  };
};

# IV - Второй Прогон
$mdfState = 1;
foreach my $key (keys %MDF) {
    if ($dbglvl) { &wrlog("WARN [Second Run] MIB-файл отправлен на импорт parse_file('$MDF{$key}', '$key')"); };
    print "Внимание! Вторично пытаемся импортировать файл '$MDF{$key}' из-за ошибок импорта!\n";
    $already_parsed{$MDF{$key}} = 0;
    parse_file($MDF{$key}, $key);
};

# V - Записываем все Трапы в форматированный файл trap_mgr.conf
if ($dbglvl) {
  my $count=0;
  &wrlog('DEBUG ALL %OIDS OBJECTS BEGIN');
  foreach my $key (keys %OIDS) {
    if(exists($OIDS{$key})){
      &wrlog("$key = $OIDS{$key}");
      $count++;
    };
  };
  &wrlog("DEBUG OBJECTS $count END");
  if ($dbglvl >=4) { print Dumper(%OIDS), "\n"; };
};

# Revers OIDs Hash
my %OIDSREV = reverse %OIDS;

# Create a hash of "Root" Enterprise OIDs
if ($dbglvl) {
  my %entOID;
  foreach my $key (sort keys %OIDSREV) {
    if ($key =~ /$OIDS{enterprises}\.\d+$/) {
      $entOID{$key} = $OIDSREV{$key};
      &wrlog("Reversed Enterprise OID: $key - $OIDSREV{$key}\n");
    };
  };
};

if (open(my $fo, '>:encoding(UTF-8)', $trapmgrfile)) {
  binmode($fo, ":utf8");

  # Write out the DEFAULTS for trap_mgr.conf
  if ($stdsection) {
    print $fo "BEGIN_DEFAULTS\n";
    print $fo "        ClassName:          SNMPTrap\n";
    print $fo "        InstanceName:       \$SYS\$\n";
    print $fo "        EventName:          \$E\$ \$N\$ \$S\$\n";
    print $fo "        Severity:           2\n";
    print $fo "        EventText: Varbinds \$V*\$\n";
    print $fo "        Expiration:         0\n";
    print $fo "        State:              NOTIFY\n";
    print $fo "        InMaintenance:      FALSE\n";
    print $fo "        ClearOnAcknowledge: TRUE\n";
    print $fo "        EventType:          MOMENTARY\n";
    print $fo "        SysNameOrAddr:      \$A\$\n";
    print $fo "        UnknownAgent:       IGNORE\n";
    print $fo "        LogFile:            Trap_mgr.log\n";
    print $fo "END_DEFAULTS\n\n";
  };

  # Генерируем содержимое файла
  foreach my $oid (keys %TrapMgr) {

    if ($oid =~ m%HASH%){
      # Великий костыль против undef
      if ($dbglvl) { &wrlog("ERR FAILED OID: $oid [$TrapMgr{$oid}]"); };
      print "FAILED OID: $oid [$TrapMgr{$oid}]\n";
      delete($TrapMgr{$oid});
      next;
    };

    $oid =~ s/\.+/\./sg;
    my @cnt = split(/\./, $oid);
    my @oidbuild;
    for (my $dt = 1; $dt<=7; $dt++){ if(defined($cnt[$dt]) && ($cnt[$dt])) { push(@oidbuild, $cnt[$dt]); }; };
    my $enteroid = '.' . join('.', @oidbuild);
    $enteroid =~ s/\.*$//s;

    my $EntName = $OIDSREV{$enteroid};
    if ($EntName) {
      if ($dbglvl) { &wrlog("The '$EntName' => OID: '$oid' traps are:"); };
    };

    # Создаём ХЭШ, чтобы использовать позже. Так мы можем
    # видеть если определённый ТРАП существует в нашем листе.
    my %tst;
    for my $ttrap ( @{ $TrapMgr{$oid}{TRAPS} } ) {
      $tst{$ttrap->{name}}++;
      if ($dbglvl) { &wrlog("Trapname: '", $ttrap->{name}, "' Count: '", $tst{$ttrap->{name}}, "'"); };
    };

    for my $ttrap ( @{ $TrapMgr{$oid}{TRAPS} } ) {
      my $offtype = $ttrap->{name};
      my $ontype = $ttrap->{name};
      my $uptype = $ttrap->{name};
      my $downtype = $ttrap->{name};
      my $detectype = $ttrap->{name};
      my $cleartype = $ttrap->{name};
      $downtype =~ s/Down/Up/i;
      $uptype =~ s/Up/Down/i;
      $offtype =~ s/Off/On/i;
      $ontype =~ s/On/Off/i;
      $detectype =~ s/Detected/Cleared/i;
      $cleartype =~ s/Cleared/Detected/i;
      # If we have a Down Message with a matching Up
      if (($ttrap->{name} =~ /Down/i) && ($tst{$downtype})) {

        if ($dbglvl) { &wrlog("Found Downtype Message = $tst{$downtype} = $downtype"); };

        # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $ttrap->{name}\n";
        print $fo "        Severity:           $ttrap->{severity}\n";
        my $v_cnt = $#{ $ttrap->{varbinds} } + 1; # size of list of variables
        if ($v_cnt) {
          print $fo "        UserDefined2:     The $v_cnt Varibles are - ";
          for (my $i=0; $i < $v_cnt; $i++) {
            print $fo $ttrap->{varbinds}[$i], " = \$V",$i+1,"\$ ";
          }
          print $fo "\n";
        }
        print $fo "        EventType:          DURABLE\n";
        print $fo "        State:              NOTIFY\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "        ClearOnAcknowledge: TRUE\n";
        print $fo "        SysNameOrAddr:      \$A\$\n";
        print $fo "END_TRAP\n\n";
      }
      # If we have an Up Message with a matching Down
      elsif (($ttrap->{name} =~ /Up/i) && ($tst{$uptype})) {
        if ($dbglvl) { &wrlog("Found UpType Message = $tst{$uptype} = $uptype"); };
        # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $uptype\n";
        print $fo "        State:              CLEAR\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "        SysNameOrAddr:      \$A\$\n";
        print $fo "END_TRAP\n\n";
      }
      # If we have a On Message with a matching Off
      elsif (($ttrap->{name} =~ /On/i) && ($tst{$ontype})) {
        if ($dbglvl) { &wrlog("Found Ontype Message = $tst{$ontype} = $ontype"); }
        # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $ttrap->{name}\n";
        print $fo "        Severity:           $ttrap->{severity}\n";
        my $v_cnt = $#{ $ttrap->{varbinds} } + 1; # size of list of variables
        if ($v_cnt) {
          print $fo "        UserDefined2:       $ttrap->{name} ($EntName), The $v_cnt Varibles are - ";
          for (my $i=0; $i < $v_cnt; $i++) {
            print $fo $ttrap->{varbinds}[$i], " = \$V", $i+1, "\$  ";
          }
          print $fo "\n";
        };
        print $fo "        EventType:          DURABLE\n";
        print $fo "        State:              NOTIFY\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "        ClearOnAcknowledge: TRUE\n";
        print $fo "        SysNameOrAddr:      \$A\$\n";
        print $fo "END_TRAP\n\n";
      }
      # If we have an Off Message with a matching On
      elsif (($ttrap->{name} =~ /Off/i) && ($tst{$offtype})) {
        if ($dbglvl) { &wrlog("Found OffType Message = $tst{$offtype} = $offtype"); };
        # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $offtype\n";
        print $fo "        State:              CLEAR\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "        SysNameOrAddr:      \$A\$\n";
        print $fo "END_TRAP\n\n";
      }
      # If we have a Detected Message with a matching Cleared
      elsif (($ttrap->{name} =~ /Detected/i) && ($tst{$detectype})) {
        if ($dbglvl) { &wrlog("Found detectype Message = $tst{$detectype} = $detectype"); };
        # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $ttrap->{name}\n";
        print $fo "        Severity:           $ttrap->{severity}\n";
        my $v_cnt = $#{ $ttrap->{varbinds} } + 1; # size of list of variables
        if ($v_cnt) {
          print $fo "        UserDefined2:       $ttrap->{name} ($EntName), The $v_cnt Varibles are - ";
          for (my $i=0; $i < $v_cnt; $i++) {
            print $fo $ttrap->{varbinds}[$i], " = \$V", $i+1, "\$  ";
          };
          print $fo "\n";
        };
        print $fo "        EventType:          DURABLE\n";
        print $fo "        State:              NOTIFY\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "        ClearOnAcknowledge: TRUE\n";
        print $fo "        SysNameOrAddr:      \$A\$\n";
        print $fo "END_TRAP\n\n";
      }
      # If we have an Cleared Message with a matching Detected
      elsif (($ttrap->{name} =~ /Cleared/i) && ($tst{$cleartype})) {
        if ($dbglvl) { &wrlog("Found clearType Message = $tst{$cleartype} = $cleartype"); };
        # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $cleartype\n";
        print $fo "        State:              CLEAR\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "END_TRAP\n\n";
      }
      else { # -- Write out the Trap Definition --
        print $fo "# $ttrap->{name}\n";
        print $fo "BEGIN_TRAP $oid $ttrap->{generic} $ttrap->{specific}\n";
        print $fo "        ClassName:          Host\n";
        print $fo "        InstanceName:       \$SYS\$\n";
        print $fo "        EventName:          $ttrap->{name}\n";
        print $fo "        Severity:           $ttrap->{severity}\n";
        my $v_cnt = $#{ $ttrap->{varbinds} } + 1; # size of list of variables
        if ($v_cnt) {
          print $fo "        UserDefined2:       The $v_cnt Varibles are - ";
          if ($dbglvl) { &wrlog("Varbinds Count: $v_cnt"); };
          for (my $i=0; $i < $v_cnt; $i++) {
            print $fo $ttrap->{varbinds}[$i], " = \$V", $i+1, "\$  ";
          };
          print $fo "\n";
        };
        print $fo "        Expiration:         $experation\n";
        print $fo "        EventType:          MOMENTARY\n";
        print $fo "        State:              NOTIFY\n";
        print $fo "        UserDefined1:       \$*\$\n";
        print $fo "        UserDefined3:       \$E\$\n";
        print $fo "        EventText:          $ttrap->{description}\n";
        print $fo "        ClearOnAcknowledge: TRUE\n";
        print $fo "        SysNameOrAddr:      \$A\$\n";
        print $fo "END_TRAP\n\n";
      };

      if ($dbglvl) {
        my $vbsize = $#{ $ttrap->{varbinds} }; # size of array
        &wrlog("$ttrap->{name} - $ttrap->{generic} - $ttrap->{specific} - Varbinds Size: $vbsize");
        my $mervbtext = '';
        for (my $i=0; $i <= $vbsize; $i++) {
          $mervbtext = $mervbtext."$ttrap->{varbinds}[$i] - ";
        };
        &wrlog("Varbinds: $mervbtext");
        &wrlog("Severity: $ttrap->{severity}");
        &wrlog("Description: $ttrap->{description}");
      };

    };
  }

} else {
  if ($dbglvl) { &wrlog("WARN Не удаётся открыть файл '$trapmgrfile' на запись: $!"); };
};

if ($dbglvl) {
  my $ts = &timestamp;
  print $logfile "\n\n$ts All Done!!!\n";
  close($logfile);
  print "\nAll Done!!!\n";
};





#-- Subroutines ---------------------------------------------------------------#

#------------------------------------------------------------------------------#
# parse_file(filepath, filekey)
#------------------------------------------------------------------------------#

sub parse_file {
  my ($curfile, $filekey) = @_;
  my $ismib = 0;

  if ($already_parsed{$curfile}){
    if ($dbglvl) { &wrlog("WARN Файл '$curfile' Уже Импортирован"); };
    return;
  };
  $already_parsed{$curfile} = 1;

  if ($dbglvl) { &wrlog("INFO Начинаем разбор MIB-файла '$curfile'"); };

  local $lineCtr = 0;
  local $Ent = "";
  local @VarBinds = ( );
  local $Descr = "";
  local %TRAPS = ( );
  local $Severity = 0;

    if (open(my $fi, '<:encoding(UTF-8)', $curfile))
    {
      binmode($fi, ":utf8");
      $lineCtr = 0;
      my $prevline = '';
      while (my $row = <$fi>)
      {
        # Read each line of each MIB file and Parse
        $lineCtr++;
        $row =~ s/\r?\n$//sg; # Убираем \r\n
        chomp($row);          # Убираем новые линии
        $row =~ s/--.*$//s;   # Убираем комментарии начинающиеся с --
        $row =~ s/{/{\ /sg;   # 2013-04-10 Техносерв 2017-02-03 NVG Модифицирован
        $row =~ s/}/\ }/sg;   # Paste whitespace after '{' and before '}' for true parsing        
        $row =~ s/^\s+//sg;   # Убираем пробелы перед текстом
        $row =~ s/\s+/\ /sg;  # Меняем несколько пробелов на один
        $row =~ s/\s+$//sg;   # Убираем пробелы после текста
        next unless length($row);
        if ($dbglvl >= 2) { &wrlog("LN $lineCtr = $row"); };
        local @LINE=split(/\s+/, $row);

        if(!$ismib){
          if ( (($LINE[0]) && ($LINE[1]) && ($LINE[2]) && ($LINE[3])) && (($LINE[1] eq "DEFINITIONS") && ($LINE[2] eq "::=") && ($LINE[3] eq "BEGIN")) ) {
            $ismib = 1;
            if (lc($LINE[0]) ne lc($filekey)){
              if ($dbglvl) { &wrlog("ERR Внимание! Название файла '$curfile' отличается от содержимого его первой строки: '$LINE[0]'! Путь к MIB-файлу добавлен в \%MibFilesLibs под именем '$LINE[0]'!"); };
              print "Внимание! Название файла '$curfile' отличается от содержимого его первой строки: '$LINE[0]'! Путь к MIB-файлу добавлен в \%MibFilesLibs под именем '$LINE[0]'!\n";
              $MibFilesLibs{lc($LINE[0])} = $curfile;
            };
            next;
          } else {
            if ($dbglvl) { &wrlog("ERR Внимание! Файл '$curfile' не является MIB-файлом по RFC! Пропускаем!"); };
            print "Внимание! Файл '$curfile' не является MIB-файлом по RFC! Пропускаем!\n";
            return;
          };
        };

        if ( $LINE[0] eq "IMPORTS" ) {
          my $text = join(' ', @LINE);
          while ( $text !~ m{\;} ) {
            my $str = <$fi>;
            $str =~ s/\r?\n$//sg; # Убираем \r\n
            chomp($str);          # Убираем новые линии
            $str =~ s/--.*$//s;   # Убираем комментарии начинающиеся с --
            $str =~ s/^\s+//sg;   # Убираем пробелы перед текстом
            $str =~ s/\s+/\ /sg;  # Меняем несколько пробелов на один
            $str =~ s/\s+$//sg;   # Убираем пробелы после текста
            next unless length($str);
            $text .= " $str ";
          };

          $text =~ s/\s+/\ /sg;
          $text =~ s/\s*;\s*$//s;

          if ($dbglvl >= 2) { &wrlog("LN AG = $text"); };

          my @parsedtext = split(/\s+/, $text);
          for (my $i = 0; $i < $#parsedtext; $i++) {
            if ( $parsedtext[$i] eq "FROM" ) {
              if (exists($MibFilesMain{lc($parsedtext[$i+1])})) {
                parse_file($MibFilesMain{lc($parsedtext[$i+1])}, lc($parsedtext[$i+1]));
              } elsif (exists($MibFilesLibs{lc($parsedtext[$i+1])})) {
                parse_file($MibFilesLibs{lc($parsedtext[$i+1])}, lc($parsedtext[$i+1]));
              } else {
                if ($dbglvl) { &wrlog("ERR Внимание! Файл [$parsedtext[$i+1].(mib|txt|my)] необходимый для [$curfile] не найден! Ошибки импорта неизбежны!"); };
                print "Внимание! Файл [$parsedtext[$i+1].(mib|txt|my)] необходимый для [$curfile] не найден! Ошибки импорта неизбежны!\n";
              }
            }
          };
          next;
        } # End Imports

        # MODULE-IDENTITY and OBJECT-IDENTITY Section
        # treat them the same way
        if (($LINE[1]) && (($LINE[1] eq "MODULE-IDENTITY") || ($LINE[1] eq "OBJECT-IDENTITY"))) {
          # sample line
          # entityMIB  MODULE-IDENTITY
          # $ModLine[0]          1
          $MibType = "MODULE";
          $ModName = $LINE[0];

          if ($dbglvl) {
            if (@LINE > 2) { # More on this line
              &wrlog("WARN Parse Modline: Did not expect to parse anymore -> [", join(' ', @LINE) , "]");
            };

            &wrlog("Modline: $LINE[0] - $LINE[1]");
          };

          next;
        };

        # Previous Line OBJECT IDENTIFIER Check Section
        if ((($LINE[0]) && ($LINE[1]) && (($LINE[2]))) && (($LINE[0] eq "OBJECT") && ($LINE[1] eq "IDENTIFIER") && ($LINE[2] eq "::="))) {
          unshift(@LINE, $prevline);
          if ($dbglvl) { &wrlog('WARN Next Line Problem Detected in "OBJECT IDENTIFIER" Section! Previous Line UnShifted! Now @LINE:', "'@LINE'"); };
        };

        # OBJECT IDENTIFIER and OBJECT-TYPE Section
        if ( ( (($LINE[1]) && ($LINE[2])) && ( ($LINE[1] eq "OBJECT") && ($LINE[2] eq "IDENTIFIER") ) ) || ( ($LINE[1]) && ($LINE[1] eq "OBJECT-TYPE") ) ) {
          my $text = join(' ', @LINE);
          if($text =~ m/SYNTAX/){ # Костыль против ложных срабатываний словосочетания "SYNTAX OBJECT IDENTIFIER" в секции OBJECT-TYPE
            if ($dbglvl) { &wrlog('WARN SOI Detected:', $text); };
            next;
          };
          while ($text !~ m%\}%) {
            # Если строка содержит признак конца массива данных --> "}", выводим её на экран, иначе берём ещё одну строку:
            my $temp = <$fi>; # Вытаскиваем следующую строку из файла
            $temp =~ s/\r?\n$//sg; # Убираем \r\n
            chomp($temp);          # Убираем новые линии
            $temp =~ s/--.*$//s;   # Убираем каменты
            $temp =~ s/^\s*//sg;   # Убираем пробелы перед текстом
            $temp =~ s/\s*$//sg;   # Убираем пробелы после текста
            next unless length($temp); # Пропускаем пустую строку
            $temp =~ s/{/{ /sg;    # Добавляем пробел после {
            $temp =~ s/}/ }/sg;    # Добавляем пробел перед }
            # Пропускаем строку, если в ней нет признака начала данных
            next unless (($temp =~ m%::=%) || ($text =~ m%::=%));
            $text .= " $temp";     # Добавляем прочитанное в строку
          };

          $text =~ s/\s+/\ /sg; # Меняем несколько пробелов на один
          $text =~ s/^\s*//sg;  # Убираем пробелы перед текстом
          $text =~ s/\s*$//sg;  # Убираем пробелы после текста

          if ($dbglvl >= 2) { &wrlog("LN AG = $text"); };

          # Костыль против SEQUENCE — этот раздел не должен попадать в %OIDS
          if ($text =~ m/::=\s+SEQUENCE\s+{/) {
            if ($dbglvl) {
              &wrlog("WARN Зафиксирована попытка случайной обработки секции 'SEQUENCE'. Пропускаем!");
            };
            next;
          };

          # gbgTrap OBJECT IDENTIFIER ::= { scn 2 }
          # internet OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }

          if(($LINE[0]) && (exists($OIDS{$LINE[0]}))){ # Проверяем, нет ли уже такого OID'а в хеше %OIDS.
            if ($dbglvl) { &wrlog("WARN OID $OIDS{$LINE[0]} ($LINE[0]) Уже импортирован! Пропускаем!"); };
          }elsif($text=~/\{\s*(.*?)\s*\}/){
            # Механизм сборки OID'а
            my @complex_oid = split(/\s+/, $1);
            my $string_oid = '';
            foreach my $value (@complex_oid){
              if($value=~/^[a-z-_\d]+\((\d+)\)$/i){ # Если значение вроде org(3) или dod(6), берём число из скобок.
                $string_oid = $string_oid.'.'.$1;
              }elsif($value=~/^(\d+)$/){ # Если просто число, добавляем его в строку как есть.
                $string_oid = $string_oid.'.'.$1;
              }elsif($value=~/^([a-z-_\d]+)$/i){ # Если это iso, internet, private и т.д. резолвим из %OIDS и сообщаем если не существует!
                if (exists($OIDS{$1})){
                  $string_oid = $string_oid.'.'.$OIDS{$1};
                }else{
                  if(!$mdfState){
                    if ($dbglvl) { &wrlog('ERR Необходмый для "'.$ModName.'" родительский элемент "'.$value.'" ранее не был загружен в массив %OIDS! Файл направлен на повторный импорт!'); };
                    if (!exists($MDF{$filekey})){$MDF{$filekey} = $curfile};
                  }else{
                    if ($dbglvl) { &wrlog('CRIT Второй прогон! Необходмый для "'.$ModName.'" родительский элемент "'.$value.'" ранее не был загружен в массив %OIDS!'); };
                    print 'КРИТИЧНО! Необходмый для "'.$ModName.'" родительский элемент "'.$value.'" ранее не был загружен в массив %OIDS'."!\n";
                  };
                  $string_oid = ''; # Сбрасываем добавление элемента, т.к. данные по нему не полны.
                  last;
                };
              };
            };
            $string_oid =~ s/\.+/\./sg; # Убираем возможное задваивание точек
            if($string_oid ne ''){
              $OIDS{$LINE[0]} = $string_oid; # Добавляем получившееся значение в хеш %OIDS
            }else{
              if(!$mdfState){
                if ($dbglvl) { &wrlog("WARN Родительский OID не найден для дочернего элемента '$ModName' из файла '$curfile'. Файл направлен на повторный импорт!"); };
                if (!exists($MDF{$filekey})){$MDF{$filekey} = $curfile};
              } else {
                if ($dbglvl) { &wrlog("ERR Родительский OID не найден, дочерний элемент '$ModName' из файла '$curfile' загружен не будет!"); };
                print "Родительский OID не найден, дочерний элемент '$ModName' из файла '$curfile' загружен не будет!\n";
              };
              next;
            };
          }else{
            if ($dbglvl) { &wrlog("ERR Несмотря на преобразования, в файле не найдены данные из фигурных скобок. (MIB файл битый или отсутствует)"); };
            print "Несмотря на преобразования, в файле не найдены данные из фигурных скобок. (MIB файл битый или отсутствует)\n";
            next;
          };
        };

        # NOTIFICATION-TYPE section (V2 type traps)
        if (($LINE[1]) && ($LINE[1] eq "NOTIFICATION-TYPE")) {
          # sample line
          # lerAlarmOn NOTIFICATION-TYPE
          # $TrapLine[0] 1

          $MibType = "NOTIFICATION";
          $TrapName = $LINE[0];

          if ($dbglvl) {
            if (@LINE > 2) {
              # More on this line
              &wrlog("WARN Parse Notif: Did not expect to parse anymore -> [", join(' ', @LINE) , "]");
            };
            &wrlog("Trap Line: [", join(' ', @LINE), "]");
          };

          # End of TRAP-TYPE Parse
          next;
        };

        # TRAP-TYPE section (V1 type traps)
        if (($LINE[1]) && ($LINE[1] eq "TRAP-TYPE")) {
          # sample line
          # IV_Trap_Minor TRAP-TYPE
          # $TrapLine[0] 1

          $MibType = "TRAP";
          $TrapName = $LINE[0];

          if ($dbglvl) {
            if (@LINE > 2) {
              # More on this line
              &wrlog("WARN Parse Trap: Did not expect to parse anymore -> [", join(' ', @LINE) , "]");
            };
            &wrlog("Trap Line: ", join(' ', @LINE));
          };

          # End of TRAP-TYPE Parse
          next;
        };

        # ENTERPRISE line
        if (($LINE[0]) && ($LINE[0] eq "ENTERPRISE")) {
          $Ent = $LINE[1];
          if ($dbglvl) { &wrlog("Enterprise = $Ent of $LINE[1]"); };
        };

        # VARIABLE line
        if (($LINE[0]) && (($LINE[0] eq "VARIABLES") || ($LINE[0] eq "OBJECTS"))) {
          @VarBinds = (); # Очищаем @VarBinds от предидущих данных
          shift(@LINE); # Убирает тип из строки, если тип, скобка и значение в одну строку.
          my $text = join('',@LINE); # Между запятыми пробелы не нужны.
          while ( $text !~ m{\}} ) {
            my $str = <$fi>;
            $str =~ s/\r?\n$//sg;
            chomp($str);
            $str =~ s/--.*$//s;
            $str =~ s/\s+//sg;
            next unless length($str);
            $text .= $str;
          };
          $text =~ s/^[\,\s]*\{\s*//s;
          $text =~ s/\s+//sg;
          $text =~ s/\,+/\,/sg;
          $text =~ s/^\,//s;
          $text =~ s/[\,\s]*\}.*$//s;
          if ($dbglvl >= 2) { &wrlog("LN AG = $text"); };
          push(@VarBinds, split(/\,/,$text));
        };

        # DESCRIPTION line
        if (($LINE[0]) && ($LINE[0] eq "DESCRIPTION")) {
          $Descr = ""; # Reset the Descr var
          shift(@LINE); # Убирает тип из строки, если тип, скобка и значение в одну строку.
          my $text = join(' ',@LINE);
          $text =~ s/\r?\n$//sg;
          chomp($text);
          $text =~ s/\s+/\ /sg;
          $text =~ s/^\s+//s;
          $text =~ s/\s+$//s;
          while ( $text !~ m{\"$} ) {
            my $str = <$fi>;
            $str =~ s/\r?\n$//sg;
            chomp($str);
            $str =~ s/--.*$//s;
            $str =~ s/^\s+//s;
            $str =~ s/\s+/\ /sg;
            $str =~ s/\s+$//s;
            next unless length($str);
            $text .= " $str";
          };
          $text =~ s/^\s*\"\s*//s;
          $text =~ s/\s+/\ /sg;
          $text =~ s/\,+/\,/sg;
          $text =~ s/\s*\".*$//s;
          $Descr = $Descr.' '.$text;
          $Descr =~ s/^\s+//s;
        };

        if (($LINE[0]) && ($LINE[0] eq "::=")) {
          if ($MibType eq "MODULE") { # MODULE-IDENTITY Data Section
            my $text = join(' ', @LINE);
            while ($text !~ m%\}%) {
              # Если строка содержит признак конца массива данных --> "}", выводим её на экран, иначе берём ещё одну строку:
              my $temp = <$fi>; # Вытаскиваем следующую строку из файла
              $temp =~ s/\r?\n$//sg; # Убираем \r\n
              chomp($temp);          # Убираем новые линии
              $temp =~ s/--.*$//s;   # Убираем каменты
              $temp =~ s/^\s*//sg;   # Убираем пробелы перед текстом
              $temp =~ s/\s*$//sg;   # Убираем пробелы после текста
              next unless length($temp); # Пропускаем пустую строку
              $temp =~ s/{/{ /sg;    # Добавляем пробел после {
              $temp =~ s/}/ }/sg;    # Добавляем пробел перед }
              # Пропускаем строку, если в ней нет признака начала данных
              next unless (($temp =~ m%::=%) || ($text =~ m%::=%));
              $text .= " $temp";     # Добавляем прочитанное в строку
            };

            $text =~ s/\s+/\ /sg; # Меняем несколько пробелов на один
            $text =~ s/^\s*//sg;  # Убираем пробелы перед текстом
            $text =~ s/\s*$//sg;  # Убираем пробелы после текста

            if ($dbglvl >= 2) { &wrlog("LN AG = $text"); };

            if($text=~/\{\s*(.*?)\s*\}/){
              # Механизм сборки OID'а
              my @complex_oid = split(/\s+/, $1);
              my $string_oid = '';
              foreach my $value (@complex_oid){
                if($value=~/^\[a-z-_\d]+\((\d+)\)$/i){ # Если значение вроде org(3) или dod(6), берём число из скобок.
                  $string_oid = $string_oid.'.'.$1;
                }elsif($value=~/^(\d+)$/){ # Если просто число, добавляем его в строку как есть.
                  $string_oid = $string_oid.'.'.$1;
                }elsif($value=~/^([a-z-_\d]+)$/i){ # Если это iso, internet, private и т.д. резолвим из %OIDS и сообщаем если не существует!
                  if (exists($OIDS{$1})){
                    $string_oid = $string_oid.'.'.$OIDS{$1};
                  }else{
                    if(!$mdfState){
                      if ($dbglvl) { &wrlog('ERR Необходмый для "'.$ModName.'" родительский элемент "'.$value.'" ранее не был загружен в массив %OIDS! Файл направлен на повторный импорт!'); };
                      if (!exists($MDF{$filekey})){$MDF{$filekey} = $curfile};
                    }else{
                      if ($dbglvl) { &wrlog('CRIT Второй прогон! Необходмый для "'.$ModName.'" родительский элемент "'.$value.'" ранее не был загружен в массив %OIDS!'); };
                      print 'КРИТИЧНО! Необходмый для "'.$ModName.'" родительский элемент "'.$value.'" ранее не был загружен в массив %OIDS'."!\n";
                    };
                    $string_oid = ''; # Сбрасываем добавление элемента, т.к. данные по нему не полны.
                    last;
                  };
                };
              };
              $string_oid =~ s/\.+/\./sg; # Убираем возможное задваивание точек
              if($string_oid ne ''){
                $OIDS{$ModName} = $string_oid; # Добавляем получившееся значение в хеш %OIDS
              }else{
                if(!$mdfState){
                  if ($dbglvl) { &wrlog("WARN Родительский OID не найден для дочернего элемента '$ModName' из файла '$curfile'. Файл направлен на повторный импорт!"); };
                  if (!exists($MDF{$filekey})){$MDF{$filekey} = $curfile};
                } else {
                  if ($dbglvl) { &wrlog("ERR Родительский OID не найден, дочерний элемент '$ModName' из файла '$curfile' загружен не будет!"); };
                  print "Родительский OID не найден, дочерний элемент '$ModName' из файла '$curfile' загружен не будет!\n";
                };
                next;
              };
            }else{
              if ($dbglvl) { &wrlog("ERR Несмотря на преобразования, в файле не найдены данные из фигурных скобок. (MIB файл битый)"); };
              print "Несмотря на преобразования, в файле не найдены данные из фигурных скобок. (MIB файл битый)\n";
              next;
            };

          };

          # Если мы сейчас в TRAP-TYPE или NOTIFICATION-TYPE секции
          if (($MibType eq "TRAP") || ($MibType eq "NOTIFICATION")) {
            if ($LINE[1] ne "{") {
              $TrapNumber = $LINE[1];
            } elsif ($LINE[1] eq "{") {

              if (exists($OIDS{$LINE[2]})) {
                if ($dbglvl) { &wrlog("DEFINED $LINE[2]: $OIDS{$LINE[2]}"); };
                # Если OID найдем в хеше %OIDS, то берём его значение
                $Ent = $OIDS{$LINE[2]};
                if ($LINE[3] =~ /(\d+)\}/) {
                  $LINE[3] = $1;
                };
                $TrapNumber = $LINE[3];
                if ($dbglvl) { &wrlog("Notification-Type [$TrapName] = $LINE[2]\.$LINE[3]"); };
              } else {
                #$Ent = $LINE[2]; # NVG 2016.11.25 так попадали текстовые данные в ХЕШ %OIDS
                if(!$mdfState){
                  if ($dbglvl) { &wrlog("ERR Не удалось найти OID родительский элемент '$LINE[2]' для трапа '$TrapName'! Файл направлен на повторный импорт!"); };
                  if (!exists($MDF{$filekey})){$MDF{$filekey} = $curfile};
                }else{
                  if ($dbglvl) { &wrlog("CRIT Второй прогон! Не удалось найти OID родительский элемент '$LINE[2]' для трапа '$TrapName'!"); };
                  print "КРИТИЧНО! Не удалось найти OID родительский элемент '$LINE[2]' для трапа '$TrapName'\n";
                };
                next;
              };

            };
          };

          if (($MibType eq "TRAP") || ($MibType eq "NOTIFICATION")) {
            # Только ТРАПЫ или НОТИФИКАЦИИ берём в обработку

            if (exists($OIDS{$Ent})) {
              # Если в хеше %OIDS есть такой OID, то берём в работу его значение
              $Ent = $OIDS{$Ent};
            } else {
              # Иначе 
              if ($dbglvl) {
                if ($Ent) { &wrlog("UNDEF Ent in OIDs '$Ent'"); }
                else { &wrlog("UNDEF Ent Value"); }
              };
            };

            # For some reason, we need to remove the Trailing .0 on the OID
            $TrapOID = $Ent;

            # Mы не смогли понять что это за "some reason" но удалять .0 из OID не корректно.
            # Техносерв 24.03.14

            # NVG 2016: Мы разобрались, что и зачем. ЛОЛ)
            # Убираем последний ноль и точку перед ним из OID'а, если такое сочетание имеется.
            $TrapOID =~ s/\.0$//;


            # Устанавливаем Severity
            $Severity = "4";  # Default
            # Normal - Should be a clear of some sort
            if (($TrapName =~ /Normal|Clear/i ) || ($Descr =~ /Normal|Clear/i )) {
              $Severity = "5";
            }
            # Minor Trap
            elsif (($TrapName =~ /Minor|Flt|Fault|On/i) || ($Descr =~ /Minor|Flt|Fault|On/i)) {
              $Severity = "3";
            }
            # Major Trap
            elsif (($TrapName =~ /Fail|Down|Major/i ) || ($Descr =~ /Fail|Down|Major/i )) {
              $Severity = "2";
            }
            # Critical Trap
            elsif (($TrapName =~ /Critical/i) || ($Descr =~ /Critical/i)) {
              $Severity = "1";
            }

            if ($dbglvl) {
              # A lot of printing for debugging purposes
              &wrlog("TrapName: $TrapName");
              &wrlog("Enterprise: $Ent");
              &wrlog("VarBinds Count: [", $#VarBinds+1, "]");
              my $tempvarbinds = '';
              for (my $i = 0; $i <= $#VarBinds; $i++) {
                $tempvarbinds = $tempvarbinds." ".$VarBinds[$i];
              };
              &wrlog("VarBinds: $tempvarbinds");
              &wrlog("Description: $Descr");
              &wrlog("TrapOID: $TrapOID");
              &wrlog("Generic Num: $generictype");
              &wrlog("TrapNumber: $TrapNumber");
              &wrlog("Severity: $Severity");
            };

            # Now Lets assign the Hash containing all the trap-mgr.conf
            # information - Hashes of Hashes
            # First, lets create an easy way to identify
            #
            # $TRAPS = {
            # SPECIFIC => $TrapNumber
            # GENERIC  => "6"
            # NAME     => $TrapName
            # VARS     => @varbinds
            # DESCR    => $Descr
            # SEVERITY => $Severity
            # }
            #
            # $trapMgr = {
            #     OID    => $TrapOID
            #     TRAP_L => { %TRAPS }
            # }
            # $TRAPS = {};
            # $TRAPS->{SPECIFIC} = $TrapNumber;
            # $TRAPS->{GENERIC} = "6";
            # $TRAPS->{NAME} = $TrapName;
            # $TRAPS->{VARS} = @varbinds;
            # $TRAPS->{DESCR} = $Descr;
            # $TRAPS->{SEVERITY} = $Severity;

            my $rec = {};
            $rec->{OID} = $TrapOID;

            my %trapInfo = ();
            $trapInfo{specific} = $TrapNumber;
            $trapInfo{generic} = $generictype;
            $trapInfo{name} = $TrapName;
            $trapInfo{varbinds} = [ @VarBinds ];
            $trapInfo{severity} = $Severity;
            $trapInfo{description} = $Descr;

            push @{ $TRAPS{$TrapOID} }, { %trapInfo };
            $rec->{TRAPS} = [ @{ $TRAPS{$TrapOID} } ];
            $TrapMgr{ $rec->{OID} } = $rec;

          };
          $MibType = ""; # done with a Section Reset MibType
        };
        $prevline = $row;
        if ($dbglvl >= 3) { print "$lineCtr = $row\n"; };

      }; # End While
      close($fi);
    } else {
      if ($dbglvl) { &wrlog("WARN Не удаётся открыть файл '$curfile' на чтение: $!"); };
    };

} # End parse_file



#------------------------------------------------------------------------------#
# Load MIBs to %MibFiles and Checking Double Files return loadmibs(%MibFiles)
#------------------------------------------------------------------------------#

sub loadmibs {
  my %MibFiles = ();
  my $crit = shift(@_);
  foreach my $mibspath (@_) {
    if ($dbglvl) { &wrlog("INFO Импортируем файлы из директории '$mibspath'"); };
    if (opendir(my $resdir,"$mibspath")) {
      foreach my $curfile (readdir($resdir)) {
        if($curfile=~/^\.|\.\.$/){next;};
        $curfile =~ s/\r?\n$//sg; # Убираем \r\n
        chomp($curfile);          # Убираем новые линии
        $curfile =~ s/#.*//s;     # Убираем комментарии начинающиеся с #
        $curfile =~ s/^\s+//sg;   # Убираем пробелы перед текстом
        $curfile =~ s/\s+$//sg;   # Убираем пробелы после текста
        next unless length($curfile);
        if ($curfile !~ /(\.mib|\.txt|\.my)$/i) {
          if ($dbglvl) { &wrlog("WARN Мусор! Файл '$mibspath/$curfile' пропущен"); };
          next;
        };

        if(-d "$mibspath/$curfile"){ if ($dbglvl) { &wrlog("WARN Мусор! Директория '$mibspath/$curfile' пропущена"); }; next; };

        if(my ($curfilename, $curfileext) = $curfile =~ /(.+)\.+(.+)$/i){
          if ($dbglvl >= 3) { &wrlog("FileName: '$curfilename', FileExt: '$curfileext'"); };

          if(exists($MibFiles{lc($curfilename)})){
            if($crit){
              print "CRITICAL ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFiles{lc($curfilename)}'\n";
              if ($dbglvl) { &wrlog("CRITICAL ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFiles{lc($curfilename)}'\n"); };
              exit(1);
            }else{
              print "ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFiles{lc($curfilename)}'\n";
              if ($dbglvl) { &wrlog("ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFiles{lc($curfilename)}'\n"); };
            };
          }
          elsif(exists($MibFilesMain{lc($curfilename)})){
            if($crit){
              print "CRITICAL ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesMain{lc($curfilename)}'\n";
              if ($dbglvl) { &wrlog("CRITICAL ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesMain{lc($curfilename)}'\n"); };
              exit(1);
            }else{
              print "ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesMain{lc($curfilename)}'\n";
              if ($dbglvl) { &wrlog("ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesMain{lc($curfilename)}'\n"); };
            };
          }
          elsif(exists($MibFilesLibs{lc($curfilename)})){
            if($crit){
              print "CRITICAL ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesLibs{lc($curfilename)}'\n";
              if ($dbglvl) { &wrlog("CRITICAL ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesLibs{lc($curfilename)}'\n"); };
              exit(1);
            }else{
              print "ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesLibs{lc($curfilename)}'\n";
              if ($dbglvl) { &wrlog("ERROR! Double File Conflict Detected: '$mibspath/$curfile' and '$MibFilesLibs{lc($curfilename)}'\n"); };
            };
          }else{
            $MibFiles{lc($curfilename)} = $mibspath.'/'.$curfile;
            if ($dbglvl) { &wrlog("INFO Файл '$mibspath/$curfile' добавлен в список MIB-файлов"); };
          };

        }elsif($curfile !~ /\./i){
          if ($dbglvl) { &wrlog("WARN Точка в файле '$curfile' не найдена. Файл без расширения?"); };
        }else{
          if ($dbglvl) { &wrlog("WARN Имя файла '$curfile' не удалось разобрать"); };
        };
      };
      closedir($resdir);
    } else {
      if ($dbglvl) { &wrlog("WARN Не удаётся открыть директорию '$mibspath' на чтение: $!"); };
    };
  };
  return %MibFiles;
};


#------------------------------------------------------------------------------#
# Time Stamp timestamp()
#------------------------------------------------------------------------------#

sub timestamp {
#  my $time = scalar(localtime); chomp($time);
#  $time =~ /(\w*)\s(\w*)\s*(\d*)\s([\d:]*)\s(\d*)/;
  my $time = strftime('%Y.%m.%d-%H.%M.%S', localtime);
  return $time;
};


#------------------------------------------------------------------------------#
# Write Log Text to File wrlog()
#------------------------------------------------------------------------------#

sub wrlog {
  my $logtext = join(" ", @_);
  $logtext=~s%[\r\n]%%g;
#  my $ts = &timestamp;
#  print $logfile "\n$ts $logtext";
  print $logfile "\n$logtext";
};


#------------------------------------------------------------------------------#
# Random String for Log MT Ident genuid()
#------------------------------------------------------------------------------#

sub genuid {
  my $buf;
  srand( time() ^ ($$ + ($$ << 15)) );
  my @v = qw ( a e i o u y );
  my @c = qw ( b c d f g h j k l m n p q r s t v w x z );
#  for (1..2){ # Double Random String Symbols (12) (if not — 6)
    my ($flip, $str) = (0,'');
    $str .= ($flip++ % 2) ? $v[rand(6)] : $c[rand(20)] for 1 .. 9;
    $str =~ s/(....)/$1 . int rand(10)/e;
    $str = ucfirst $str if rand() > 0.5;
    my $offset = rand(length($str));
    $buf.= substr($str, $offset, length($str));
    $buf.= substr($str, 0, $offset);
#  };
  return $buf;
};

close(STDERR);
