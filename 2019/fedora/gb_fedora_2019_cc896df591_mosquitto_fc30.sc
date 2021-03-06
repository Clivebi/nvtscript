if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876350" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-05-11 02:12:28 +0000 (Sat, 11 May 2019)" );
	script_name( "Fedora Update for mosquitto FEDORA-2019-cc896df591" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-cc896df591" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2BTXFZTM5ZLXR6W3GRIYELKTHAYEFBGT" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'mosquitto' package(s) announced via the FEDORA-2019-cc896df591 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Mosquitto is an open source message broker
  that implements the MQ Telemetry Transport protocol version 3.1 and 3.1.1
  MQTT provides a lightweight method of carrying out messaging using a
  publish/subscribe model. This makes it suitable for 'machine to machine'
  messaging such as with low power sensors or mobile devices such as phones,
  embedded computers or micro-controllers like the Arduino." );
	script_tag( name: "affected", value: "'mosquitto' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "mosquitto", rpm: "mosquitto~1.6.2~1.fc30", rls: "FC30" ) )){
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

