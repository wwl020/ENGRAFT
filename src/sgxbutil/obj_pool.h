//- TODO: 整个类还有待完成，先用简单的new delete代替。
#include <pthread.h>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <stdlib.h>
#ifndef SGXBUTIL_OBJ_POOL_H
#define SGXBUTIL_OBJ_POOL_H
namespace sgxbutil {
//- Object Pool ID
typedef uint64_t ObjectPoolID;
//- resource pool template
template <typename T> 
class ObjPool {
public:    
    // static pthread_mutex_t mutex_resources;
    static int count_get;
    static std::vector<T*> resources;
    inline static T* get_object() {
        return new T();
        
        // T* t = NULL;
        // ::pthread_mutex_lock(&mutex_resources);
        // if (resources.size() == 0) {
        //     resources.push_back(new T());
        // }
        // t = resources.pop_back();
        // ::pthread_mutex_unlock(&mutex_resources);
        // return t;
    }
    inline static int return_object(T* obj) {
        delete obj;
        // ::pthread_mutex_lock(&mutex_resources);
        // resources.push_back(obj);
        // ::pthread_mutex_unlock(&mutex_resources);
        // return 0;
    }
    // static void clear_up(){
    //     pthread_mutex_lock(&mutex_resources);
    //     for (size_t i = 0; i < resources.size(); i++) {
    //         delete resources[i];
    //     }
    //     resources.clear();
    //     pthread_mutex_unlock(&mutex_resources);
    //     pthread_mutex_destroy(&mutex_resources);
    // }
};
} // namespace sgxbutil
#endif
