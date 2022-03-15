if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851514" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-22 15:18:58 +0100 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-9877" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-21 10:29:00 +0000 (Fri, 21 Sep 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for rabbitmq-server (openSUSE-SU-2017:0306-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rabbitmq-server'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rabbitmq-server fixes the following issue:

  - CVE-2016-9877: An issue in Pivotal RabbitMQ caused connection
  authentication with a username/password pair to succeed if an existing
  username was provided but the password is omitted from the connection
  request. Connections that use TLS with a client-provided certificate
  were not affected (bsc#1017642)." );
	script_tag( name: "affected", value: "rabbitmq-server on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:0306-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "erlang-rabbitmq-client", rpm: "erlang-rabbitmq-client~3.5.8~3.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rabbitmq-server", rpm: "rabbitmq-server~3.5.8~3.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rabbitmq-server-plugins", rpm: "rabbitmq-server-plugins~3.5.8~3.2", rls: "openSUSELeap42.2" ) )){
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

