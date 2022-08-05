#include "producerclient.h"
#include "common.h"
#include "cls_logs.pb.h"
#include "logproducerconfig.pb.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include "result.h"
#include "error.h"
#include <stdlib.h>
using namespace tencent_log_sdk_cpp_v2;
using namespace std;

class UserResult : public CallBack
{
public:
    UserResult() = default;
    ~UserResult() = default;
    void Success(PostLogStoreLogsResponse result) override { std::cout << result.Printf() << std::endl; }
    void Fail(PostLogStoreLogsResponse result) override
    {
        std::cout << result.Printf() << std::endl;
        std::cout<<result.loggroup_.ShortDebugString().c_str()<<std::endl;
    }
};

int main(int argc, char** argv) {
    std::string region = getenv("REGION") ? getenv("REGION") : "ap-guangzhou";
    std::string ak_id = getenv("AKID") ?  getenv("AKID") : "";
    std::string ak_secret = getenv("AKSECRET") ? getenv("AKSECRET") : "";
    std::string topic = getenv("TOPIC") ? getenv("TOPIC") : "";

    string endpoint = region + ".cls.tencentcs.com";
    cout << "region:" << region << ", endpoint:" << endpoint << ", ak:" << ak_id << ", secret:" << ak_secret.length()
        << "B" << ", topic:" << topic << endl;
    if (ak_id.empty() || ak_secret.empty() || topic.empty()) {
        cout << "No config" << endl;
        exit(-1);
    }

    cls_config::LogProducerConfig config;
    config.set_endpoint(endpoint);
    config.set_acceskeyid(ak_id);
    config.set_accesskeysecret(ak_secret);
    auto client = std::make_shared<ProducerClient>(config);
    auto callback = std::make_shared<UserResult>();
    client->Start();
    cls::Log log;
    log.set_time(time(NULL));

    auto content = log.add_contents();
    content->set_key("content");
    content->set_value("this my test");
    PostLogStoreLogsResponse ret = client->PostLogStoreLogs(topic, log, callback);
    if(ret.statusCode != 0){
        cout<<ret.content<<endl;
    }
    client->LogProducerEnvDestroy();
    return 0;
}

