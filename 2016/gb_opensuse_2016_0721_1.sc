if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851232" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-03-12 06:15:07 +0100 (Sat, 12 Mar 2016)" );
	script_cve_id( "CVE-2016-1531" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for exim (openSUSE-SU-2016:0721-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update to exim 4.86.2 fixes the following issues:

  * CVE-2016-1531: local privilege escalation for set-uid root exim when
  using 'perl_startup' (boo#968844)

  Important: Exim now cleans the complete execution environment by default.
  This affects Exim and subprocesses such as transports calling other
  programs. The following new options are supported to adjust this behaviour:

  * keep_environment

  * add_environment A warning will be printed upon startup if none of these
  are configured.

  Also includes upstream changes, improvements and bug fixes:

  * Support for using the system standard CA bundle.

  * New expansion items $config_file, $config_dir, containing the file and
  directory name of the main configuration file. Also $exim_version.

  * New 'malware=' support for Avast.

  * New 'spam=' variant option for Rspamd.

  * Assorted options on malware= and spam= scanners.

  * A commandline option to write a comment into the logfile.

  * A logging option for slow DNS lookups.

  * New ${env { variable }} expansion.

  * A non-SMTP authenticator using information from TLS client
  certificates.

  * Main option 'tls_eccurve' for selecting an Elliptic Curve for TLS.

  * Main option 'dns_trust_aa' for trusting your local nameserver at the
  same level as DNSSEC." );
	script_tag( name: "affected", value: "exim on openSUSE Leap 42.1, openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0721-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "exim", rpm: "exim~4.86.2~3.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exim-debuginfo", rpm: "exim-debuginfo~4.86.2~3.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exim-debugsource", rpm: "exim-debugsource~4.86.2~3.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon", rpm: "eximon~4.86.2~3.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximon-debuginfo", rpm: "eximon-debuginfo~4.86.2~3.10.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "eximstats-html", rpm: "eximstats-html~4.86.2~3.10.1", rls: "openSUSE13.2" ) )){
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

