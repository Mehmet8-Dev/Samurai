import { useMutation, useQueryClient } from "@tanstack/react-query";
import { changePlan, startTest, stopTest } from "../api/services";
import { getErrorMessage } from "../shared/utils/errors";

export function useTestActions({ onSuccessMessage, onErrorMessage }) {
  const queryClient = useQueryClient();

  const refreshAll = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["runs"] }),
      queryClient.invalidateQueries({ queryKey: ["stats"] }),
      queryClient.invalidateQueries({ queryKey: ["billing"] }),
      queryClient.invalidateQueries({ queryKey: ["subscription"] }),
      queryClient.invalidateQueries({ queryKey: ["plans"] }),
      queryClient.invalidateQueries({ queryKey: ["me"] }),
    ]);
  };

  const startTestMutation = useMutation({
    mutationFn: startTest,
    onSuccess: async () => {
      await refreshAll();
      onSuccessMessage?.("Test çalıştırıldı.");
    },
    onError: (error) => {
      const message = getErrorMessage(error, "Test başlatılamadı");
      onErrorMessage?.(message);
    },
  });

  const stopTestMutation = useMutation({
    mutationFn: stopTest,
    onSuccess: async () => {
      await refreshAll();
      onSuccessMessage?.("Run durduruldu.");
    },
    onError: (error) => {
      const message = getErrorMessage(error, "Run durdurulamadı");
      onErrorMessage?.(message);
    },
  });

  const changePlanMutation = useMutation({
    mutationFn: changePlan,
    onSuccess: async () => {
      await refreshAll();
      onSuccessMessage?.("Abonelik planı güncellendi.");
    },
    onError: (error) => {
      const message = getErrorMessage(error, "Plan değişikliği başarısız");
      onErrorMessage?.(message);
    },
  });

  return {
    startTest: startTestMutation.mutateAsync,
    stopTest: stopTestMutation.mutateAsync,
    changePlan: changePlanMutation.mutateAsync,
    isActionPending:
      startTestMutation.isPending || stopTestMutation.isPending || changePlanMutation.isPending,
  };
}
