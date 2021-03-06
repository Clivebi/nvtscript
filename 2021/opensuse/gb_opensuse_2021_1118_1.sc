if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854048" );
	script_version( "2021-08-24T09:58:36+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 09:58:36 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 03:02:08 +0000 (Wed, 11 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for wireshark (openSUSE-SU-2021:1118-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1118-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6W7EKZQYUPQXAOOAWFBWTO3RMQTLCMXM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the openSUSE-SU-2021:1118-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wireshark fixes the following issues:

     Update wireshark to 3.4.6.

     Including a fix for:

  - DVB-S2-BB dissector infinite loop (bsc#1186790).

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'wireshark' package(s) on openSUSE Leap 15.2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libwireshark14", rpm: "libwireshark14~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark14-debuginfo", rpm: "libwireshark14-debuginfo~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap11", rpm: "libwiretap11~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap11-debuginfo", rpm: "libwiretap11-debuginfo~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil12", rpm: "libwsutil12~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil12-debuginfo", rpm: "libwsutil12-debuginfo~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debugsource", rpm: "wireshark-debugsource~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-devel", rpm: "wireshark-devel~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-ui-qt", rpm: "wireshark-ui-qt~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-ui-qt-debuginfo", rpm: "wireshark-ui-qt-debuginfo~3.4.6~lp152.2.15.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

